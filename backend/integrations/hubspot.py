import asyncio
import base64
from fastapi import Request, HTTPException
import secrets
import json
import os
import requests
from dotenv import load_dotenv
from fastapi.responses import HTMLResponse
import httpx
from redis_client import add_key_value_redis, get_value_redis, delete_key_redis
from integrations.integration_item import IntegrationItem
from urllib.parse import urlencode

load_dotenv()

CLIENT_ID = os.environ["HUBSPOT_CLIENT_ID"]
CLIENT_SECRET = os.environ["HUBSPOT_CLIENT_SECRET"]
REDIRECT_URI = "http://localhost:8000/integrations/hubspot/oauth2callback"
scope = "oauth%20crm.objects.contacts.read%20crm.objects.deals.read%20crm.objects.companies.read"


encoded_client_id_secret = base64.b64encode(
    f"{CLIENT_ID}:{CLIENT_SECRET}".encode()
).decode()


async def authorize_hubspot(user_id, org_id):
    state_data = {
        "state": secrets.token_urlsafe(32),
        "user_id": user_id,
        "org_id": org_id,
    }
    encoded_state = base64.urlsafe_b64encode(
        json.dumps(state_data).encode("utf-8")
    ).decode("utf-8")

    params = {
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": "oauth crm.objects.contacts.read crm.objects.deals.read",
        "state": encoded_state,
    }

    auth_url = f"https://app.hubspot.com/oauth/authorize?{urlencode(params)}"

    await asyncio.gather(
        add_key_value_redis(
            f"hubspot_state:{org_id}:{user_id}", json.dumps(state_data), expire=600
        ),
    )

    return auth_url


async def oauth2callback_hubspot(request: Request):
    if request.query_params.get("error"):
        raise HTTPException(status_code=400, detail=request.query_params.get("error"))
    code = request.query_params.get("code")
    encoded_state = request.query_params.get("state")
    state_data = json.loads(base64.urlsafe_b64decode(encoded_state).decode("utf-8"))

    original_state = state_data.get("state")
    user_id = state_data.get("user_id")
    org_id = state_data.get("org_id")

    saved_state = await asyncio.gather(
        get_value_redis(f"hubspot_state:{org_id}:{user_id}"),
    )

    async with httpx.AsyncClient() as client:
        response, _ = await asyncio.gather(
            client.post(
                "https://api.hubspot.com/oauth/v1/token",
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": REDIRECT_URI,
                    "client_id": CLIENT_ID,
                    "client_secret": CLIENT_SECRET,
                },
                headers={
                    "Authorization": f"Basic {encoded_client_id_secret}",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
            ),
            delete_key_redis(f"hubspot_state:{org_id}:{user_id}"),
        )

        await add_key_value_redis(
            f"hubspot_credentials:{org_id}:{user_id}",
            json.dumps(response.json()),
            expire=600,
        )

        close_windown_script = """
           <html>
            <script>
                window.close();
            </script>
            </html> 
        """

        return HTMLResponse(content=close_windown_script)


async def get_hubspot_credentials(user_id, org_id):
    credentials = await get_value_redis(f"hubspot_credentials:{org_id}:{user_id}")
    if not credentials:
        raise HTTPException(status_code=400, detail="No Credentials Found")

    await delete_key_redis(f"hubspot_credentials:{org_id}:{user_id}")

    return credentials


async def create_integration_item_metadata_object(
    response_json, item_type: str
) -> IntegrationItem:
    props_str = response_json.get("properties", "{}")
    props = json.loads(props_str) if isinstance(props_str, str) else props_str

    if item_type.lower() == "contact":

        first_name = props.get("firstname", "") or ""
        last_name = props.get("lastname", "") or ""

        name = f"{first_name} {last_name}".strip()

        if not name:
            email = props.get("email", "")
            name = email if email else "(no name)"
    else:
        name = props.get("name", "") or ""

    creation_time = props.get("createdate")
    last_modified_time = props.get("lastmodifieddate")

    integration_item = IntegrationItem(
        id=response_json.get("id"),
        type=item_type,
        name=name if name else "(no name)",
        creation_time=creation_time,
        last_modified_time=last_modified_time,
        url=None,
    )

    return integration_item


async def get_items_hubspot(credentials) -> list[dict]:

    if isinstance(credentials, str):
        credentials = json.loads(credentials)

        if isinstance(credentials, str):
            credentials = json.loads(credentials)

    headers = {
        "Authorization": f'Bearer {credentials.get("access_token")}',
        "Content-Type": "application/json",
    }

    items = []
    url = "https://api.hubapi.com/crm/v3/objects/contacts"
    params = {"limit": 10}

    async with httpx.AsyncClient() as client:
        resp = await client.get(url, headers=headers, params=params)

        if resp.status_code != 200:
            raise HTTPException(status_code=resp.status_code, detail=resp.text)

        for obj in resp.json().get("results", []):
            item = await create_integration_item_metadata_object(obj, "Contact")
            items.append(
                {
                    "id": item.id,
                    "type": item.type,
                    "name": item.name,
                    "creation_time": item.creation_time,
                    "last_modified_time": item.last_modified_time,
                    "url": item.url,
                    "parent_id": getattr(item, "parent_id", None),
                    "parent_path_or_name": getattr(item, "parent_path_or_name", None),
                }
            )

    return items
