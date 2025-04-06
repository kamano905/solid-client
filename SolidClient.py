from urllib.parse import urljoin
from cryptography.hazmat.primitives.asymmetric import ec

from request_funcs import (
    get_account_token,
    create_client_id_and_secret,
    get_access_token,
    upload_file
)


class SolidClient:
    def __init__(self, base_url: str, email: str, password: str):
        self.base_url = base_url
        self.email = email
        self.password = password
        self.client_id = None
        self.client_secret = None
        self._load_client_id_and_secret()

        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()

        self.access_token = get_access_token(
            base_url=self.base_url,
            client_id=self.client_id,
            client_secret=self.client_secret,
            private_key=self.private_key,
            public_key=self.public_key,
        )

    def _load_client_id_and_secret(self):
        try:
            with open("secrets/client_id.txt", "r") as f:
                self.client_id = f.read().strip()
            with open("secrets/client_secret.txt", "r") as f:
                self.client_secret = f.read().strip()
        except FileNotFoundError:
            print("Client ID and Secret files not found. Generating new ones.")
            auth = get_account_token(self.base_url, self.email, self.password)
            self.client_id, self.client_secret = create_client_id_and_secret(
                base_url=self.base_url,
                auth=auth,
                web_id_path="test-pod/profile/card#me"
            )
            with open("secrets/client_id.txt", "w") as f:
                f.write(self.client_id)
            with open("secrets/client_secret.txt", "w") as f:
                f.write(self.client_secret)

    def upload_file(self, file_name: str):
        upload_file(
            pod_url=urljoin(self.base_url, "test-pod/"),
            file_name=file_name,
            access_token=self.access_token,
            private_key=self.private_key,
            public_key=self.public_key,
        )


if __name__ == "__main__":
    client = SolidClient(
        base_url="https://nk2023ubuntu.tailcfd32a.ts.net/",
        email="katsutoshi.amano@koshizuka-lab.org",
        password="amano123"
    )
    client.upload_file("test.txt")
