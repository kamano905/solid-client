import base64
from urllib.parse import urljoin
import requests
from cryptography.hazmat.primitives.asymmetric import ec

from utils import create_dpop_jwt


def get_account_token(base_url: str, email: str, password: str) -> str:
    """アカウントトークンの取得。一度取得すれば永続的に使える。
    """
    index_response = requests.get(urljoin(base_url, ".account/"))
    login_url = index_response.json()["controls"]["password"]["login"]

    login_response = requests.post(
        login_url,
        headers={"Content-Type": "application/json"},
        json={
            "email": email,
            "password": password,
        },
    )
    auth = login_response.json()["authorization"]
    return auth


def create_client_id_and_secret(
        base_url: str,
        auth: str,
        web_id_path: str,
    ) -> tuple[str, str]:
    """クライアントIDとクライアントシークレットの作成。一度取得すれば永続的に使える。webIdに紐づく。
    """
    index_auth_response = requests.get(
        urljoin(base_url, ".account/"),
        headers={
            "Authorization": f"CSS-Account-Token {auth}"
        }
    )
    client_credentials_url = index_auth_response.json()["controls"]["account"]["clientCredentials"]

    client_credentials_response = requests.post(
        client_credentials_url,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"CSS-Account-Token {auth}",
        },
        json={
            "name": "my-token",
            "webId": urljoin(base_url, web_id_path),
        },
    )
    data = client_credentials_response.json()
    client_id = data["id"]
    client_secret = data["secret"]
    return client_id, client_secret


def get_access_token(
    base_url: str,
    client_id: str,
    client_secret: str,
    private_key: ec.EllipticCurvePrivateKey,
    public_key: ec.EllipticCurvePublicKey,
) -> str:
    """アクセストークンの取得。これは毎回取得する必要がある。
    """
    auth_string = f"{client_id}:{client_secret}"
    basic_auth_header = base64.b64encode(auth_string.encode("utf-8")).decode("utf-8")

    token_url = urljoin(base_url, ".oidc/token")
    headers = {
        "Authorization": f"Basic {basic_auth_header}",
        "Content-Type": "application/x-www-form-urlencoded",
        "DPoP": create_dpop_jwt(token_url, "POST", private_key, public_key),
    }
    body = {
        "grant_type": "client_credentials",
        "scope": "openid",
    }
    response = requests.post(token_url, headers=headers, data=body)
    token_data = response.json()
    access_token = token_data["access_token"]
    return access_token


def upload_file(
    pod_url: str,
    file_name: str,
    access_token: str,
    private_key: ec.EllipticCurvePrivateKey,
    public_key: ec.EllipticCurvePublicKey,
) -> None:
    """ファイルをアップロードするメソッド。
    """
    resource_url = urljoin(pod_url, file_name)
    headers = {
        "Authorization": f"DPoP {access_token}",
        "DPoP": create_dpop_jwt(resource_url, "PUT", private_key, public_key),
        "Content-Type": "text/plain",
    }
    with open(file_name, "rb") as file:
        response = requests.put(resource_url, data=file, headers=headers)
    if response.status_code == 201 or response.status_code == 205:
        print(f"File {file_name} uploaded successfully.")
    else:
        print(f"Failed to upload file {file_name}. Status code: {response.status_code}")
