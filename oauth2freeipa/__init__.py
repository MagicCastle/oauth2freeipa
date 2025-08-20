import asyncio
import shlex
import subprocess

from contextlib import contextmanager
from os import path

from jupyterhub.auth import LocalAuthenticator

from oauthenticator.generic import GenericOAuthenticator
from oauthenticator.github import GitHubOAuthenticator
from oauthenticator.cilogon import CILogonOAuthenticator

from batchspawner import SlurmSpawner

from traitlets import Unicode, Int


class LocalFreeIPAAuthenticator(LocalAuthenticator):
    """Authenticator that add system user to FreeIPA database"""

    max_add_user_retry = Int(10, config=True, help="")

    default_group = Unicode(
        "def-sponsor00",
        config=True,
        help="",
    )
    keytab_path = Unicode(
        "/etc/jupyterhub/jupyterhub.keytab",
        config=True,
        help="",
    )
    keytab_principal = Unicode(
        "jupyterhub/jupyterhub",
        config=True,
        help="",
    )
    user_add_cmd = Unicode(
        "ipa_create_user.py",
        config=True,
        help="",
    )
    pre_spawn_timeout = Int(
        30,
        config=True,
        help="How long the authenticator can wait on user creation before cancelling the spawn",
    )

    @contextmanager
    def kerberos_ticket(self):
        subprocess.run(
            ["kinit", "-kt", self.keytab_path, "-p", self.keytab_principal],
            capture_output=True,
        )
        try:
            yield
        finally:
            subprocess.run(["kdestroy", "-p", self.keytab_principal], capture_output=True)

    def system_user_exists(self, user):
        with self.kerberos_ticket():
            process = subprocess.run(["ipa", "user-show", user.name], capture_output=True)
        return process.returncode == 0

    async def pre_spawn_start(self, user, spawner):
        if not spawner.last_activity:
            # User has never spawned a Jupyter singe server before
            # we check conditions for initial spawn to be successful
            # 1. user's home exists
            # 2. When using Slurm, does the user have an account
            # We wait `pre_spawn_timeout` seconds for the conditions to be fulfilled
            # as an external process is in charge of creating the home folder
            # and the Slurm account.
            async with asyncio.timeout(self.pre_spawn_timeout):
                while not path.exists(f"/home/{user.name}"):
                    self.log.warning(f"Home folder for {user.name} is missing")
                    await asyncio.sleep(1)
                if isinstance(spawner, SlurmSpawner):
                    while len(subprocess.run(['sacctmgr', 'show', 'user', '-n', user.name], capture_output=True).stdout) == 0:
                        self.log.warning(f"Slurm account for {user.name} is missing")
                        await asyncio.sleep(1)

    def add_system_user(self, user):
        user_add_cmd = shlex.split(self.user_add_cmd) + [user.name]
        if self.default_group:
            user_add_cmd.extend(["--group", self.default_group])

        try:
            with self.kerberos_ticket():
                subprocess.run(user_add_cmd, check=True, capture_output=True)
        except OSError as e:
             raise RuntimeError(
                f"Failed to create FreeIPA user {user.name} - could not call {user_add_cmd}: {e}"
            )
        except subprocess.CalledProcessError as e:
            raise RuntimeError(
                f"Failed to create FreeIPA user {user.name} - {user_add_cmd} returned with an error: {e}"
            )

class LocalFreeIPAGenericOAuthenticator(
    LocalFreeIPAAuthenticator, GenericOAuthenticator
):
    """Mixes FreeIPA user creation and generic OAuthenticator"""


class LocalFreeIPAGitHubOAuthenticator(LocalFreeIPAAuthenticator, GitHubOAuthenticator):
    """Mixes FreeIPA user creation and GitHub OAuthenticator"""


class LocalFreeIPACILogonOAuthenticator(
    LocalFreeIPAAuthenticator, CILogonOAuthenticator
):
    """Mixes FreeIPA user creation and GitHub OAuthenticator"""
