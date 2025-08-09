import asyncio
import base64
from fastapi import Request, HTTPException
import secrets
import json
import os
from  dotenv import load_dotenv
from fastapi.responses import HTMLResponse
import httpx
from redis_client import add_key_value_redis, get_value_redis, delete_key_redis

load_dotenv()

CLIENT_ID = os.environ["HUBSPOT_CLIENT_ID"]
CLIENT_SECRET = os.environ["HUBSPOT_CLIENT_SECRET"]
REDIRECT_URI = "http://localhost:8000/integrations/hubspot/oauth2callback"
scope = "oauth"
authorization_url = f"https://app-na2.hubspot.com/oauth/authorize?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope={scope}"

encoded_client_id_secret = base64.b64encode(
    f"{CLIENT_ID}:{CLIENT_SECRET}".encode()
).decode()


async def authorize_hubspot(user_id, org_id):
    state_data = {
        "state": secrets.token_urlsafe(32),
        "user_id": user_id,
        "org_id": org_id,
    }

    encoded_state = json.dumps(state_data)

    await asyncio.gather(
        add_key_value_redis(
            f"hubspot_state:{org_id}:{user_id}", encoded_state, expire=600
        ),
        add_key_value_redis(f"hubspot_scope:{org_id}:{user_id}", scope, expire=600),
    )

    return f"{authorization_url}&state={encoded_state}"


async def oauth2callback_hubspot(request: Request):
    if request.query_params.get("error"):
        raise HTTPException(status_code=400, detail=request.query_params.get("error"))
    code = request.query_params.get("code")
    encoded_state = request.query_params.get("state")
    state_data = json.loads(encoded_state)

    original_state = state_data.get("state")
    user_id = state_data.get("user_id")
    org_id = state_data.get("org_id")

    saved_state, scope = await asyncio.gather(
        get_value_redis(f"hubspot_state:{org_id}:{user_id}"),
        get_value_redis(f"hubspot_scope:{org_id}:{user_id}"),
    )

    if not saved_state or original_state != json.loads(saved_state).get("state"):
        raise HTTPException(status_code=400, detail="State does not match")

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
    credentials = await get_value_redis(
        f'hubspot_credentials:{org_id}:{user_id}'
    )
    if not credentials:
        raise HTTPException(
            status_code=400,
            detail='No Credentials Found'
        )
        
    await delete_key_redis(f'hubspot_credentials:{org_id}:{user_id}')
    
    return credentials


async def create_integration_item_metadata_object(response_json):
    # TODO
    pass


async def get_items_hubspot(credentials):
    # TODO
    pass
