import os
from collections import deque
from http import HTTPStatus
from json import JSONDecodeError
from typing import ClassVar

from gevent.lock import Semaphore
from locust import HttpUser, between, task


def _csv_env(name: str) -> list[str]:
    return [
        value.strip()
        for value in os.getenv(name, "").split(",")
        if value.strip()
    ]


def _token_endpoint_auth_data() -> dict[str, str]:
    client_id = os.getenv("SATOIDC_LOAD_CLIENT_ID", "").strip()
    client_secret = os.getenv("SATOIDC_LOAD_CLIENT_SECRET", "").strip()
    data = {"client_id": client_id}
    if client_secret:
        data["client_secret"] = client_secret
    return data


class PublicRouteUser(HttpUser):
    wait_time = between(0.2, 1.0)

    @task(3)
    def read_discovery_metadata(self) -> None:
        self.client.get("/.well-known/openid-configuration", name="discovery")

    @task(2)
    def read_jwks(self) -> None:
        self.client.get("/.well-known/jwks.json", name="jwks")

    @task
    def read_login_page(self) -> None:
        self.client.get("/login", name="login_page")

    @task
    def read_registration_page(self) -> None:
        self.client.get("/register", name="register_page")


class TokenLifecycleUser(HttpUser):
    weight = 1 if _csv_env("SATOIDC_LOAD_REFRESH_TOKENS") else 0
    wait_time = between(0.5, 2.0)

    refresh_tokens: ClassVar[deque[str]] = deque(
        _csv_env("SATOIDC_LOAD_REFRESH_TOKENS")
    )
    access_tokens: ClassVar[deque[str]] = deque(
        _csv_env("SATOIDC_LOAD_ACCESS_TOKENS")
    )
    token_pool_lock: ClassVar[Semaphore] = Semaphore()

    def on_start(self) -> None:
        self.client_id = os.getenv("SATOIDC_LOAD_CLIENT_ID", "").strip()
        self.token_auth_data = _token_endpoint_auth_data()
        self.refresh_token = ""
        self.access_token = ""

        with self.token_pool_lock:
            if self.refresh_tokens:
                self.refresh_token = self.refresh_tokens.popleft()
            if self.access_tokens:
                self.access_token = self.access_tokens.popleft()

    @property
    def token_seed_available(self) -> bool:
        return bool(self.client_id and self.refresh_token)

    @task(2)
    def refresh_access_token(self) -> None:
        if not self.token_seed_available:
            return

        data = {
            **self.token_auth_data,
            "grant_type": "refresh_token",
            "refresh_token": self.refresh_token,
        }
        with self.client.post(
            "/oauth/token",
            data=data,
            name="oauth_token_refresh",
            catch_response=True,
        ) as response:
            if response.status_code != HTTPStatus.OK:
                response.failure("refresh token grant failed")
                return
            try:
                token_response = response.json()
            except JSONDecodeError:
                response.failure("refresh token response was not JSON")
                return

            new_refresh_token = token_response.get("refresh_token")
            new_access_token = token_response.get("access_token")
            if not new_refresh_token or not new_access_token:
                response.failure("refresh token response missing tokens")
                return

            self.refresh_token = new_refresh_token
            self.access_token = new_access_token

    @task
    def read_userinfo(self) -> None:
        if not self.access_token:
            return

        headers = {"Authorization": f"Bearer {self.access_token}"}
        with self.client.get(
            "/oauth/userinfo",
            headers=headers,
            name="oauth_userinfo",
            catch_response=True,
        ) as response:
            if response.status_code != HTTPStatus.OK:
                response.failure("userinfo request failed")
