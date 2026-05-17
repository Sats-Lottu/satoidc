from locust import HttpUser, between, task


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
