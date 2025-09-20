# In D:\EditerDashboard\components\telegram\router.py

from fastapi import APIRouter, Request, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from core.config import settings
from core.database import get_db
from components.submissions.models import VideoSubmission, SubmissionStatus, Volunteer
import logging
import httpx
import os
import json

# --- api.video Imports ---
import apivideo
from apivideo.exceptions import ApiException
from apivideo.apis import VideosApi
# -------------------------

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

router = APIRouter()
WEBHOOK_PATH = f"/webhook/{settings.SECRET_KEY}"

# --- Helper Functions (Unchanged) ---
async def get_or_create_volunteer(chat_data: dict, db: AsyncSession) -> Volunteer:
    chat_id = str(chat_data['id'])
    volunteer = await db.get(Volunteer, chat_id)
    if volunteer:
        return volunteer
    new_volunteer = Volunteer(
        id=chat_id,
        first_name=chat_data.get('first_name'),
        last_name=chat_data.get('last_name'),
        username=chat_data.get('username')
    )
    db.add(new_volunteer)
    await db.commit()
    await db.refresh(new_volunteer)
    return new_volunteer

async def get_telegram_file_path(file_id: str) -> str:
    api_url = f"https://api.telegram.org/bot{settings.TELEGRAM_BOT_TOKEN}/getFile"
    async with httpx.AsyncClient() as client:
        response = await client.post(api_url, json={"file_id": file_id})
        response.raise_for_status()
        data = response.json()
        return data["result"]["file_path"] if data.get("ok") else None

async def download_telegram_file(file_path: str, destination: str):
    file_url = f"https://api.telegram.org/file/bot{settings.TELEGRAM_BOT_TOKEN}/{file_path}"
    async with httpx.AsyncClient(timeout=120.0) as client:
        async with client.stream("GET", file_url) as response:
            response.raise_for_status()
            with open(destination, "wb") as f:
                async for chunk in response.aiter_bytes():
                    f.write(chunk)

# --- THE FINAL UPLOAD FUNCTION ---
async def upload_to_api_video(local_file_path: str, video_title: str) -> str:
    video_upload_response_object = None
    try:
        with apivideo.AuthenticatedApiClient(settings.API_VIDEO_KEY) as client:
            videos_api_instance = VideosApi(client)
            
            video_payload = {"title": video_title}
            video_container = videos_api_instance.create(video_payload)
            
            video_id = video_container.video_id
            if not video_id:
                raise ApiException("Failed to get video_id from container response.")
            
            # --- THE FINAL FIX: Open the file before uploading ---
            with open(local_file_path, "rb") as file_to_upload:
                video_upload_response_object = videos_api_instance.upload(video_id, file_to_upload)
            # ---------------------------------------------------
            
            player_url = video_upload_response_object.assets.player
            if not player_url:
                raise ApiException("Upload succeeded, but no player URL was returned.")
            
            return player_url
    finally:
        if os.path.exists(local_file_path):
            os.remove(local_file_path)
            logger.info(f"Cleaned up temporary file: {local_file_path}")

# --- Final Webhook Endpoint ---
@router.post(WEBHOOK_PATH, include_in_schema=False)
async def telegram_webhook(request: Request, db: AsyncSession = Depends(get_db)):
    update = await request.json()
    logger.info("--- NEW WEBHOOK REQUEST RECEIVED ---")
    
    try:
        message = update.get('message')
        if not message:
            return {"status": "ok, no message found"}

        video_data = None
        if 'document' in message and 'video' in message['document'].get('mime_type', ''):
            video_data = message['document']
        elif 'video' in message:
            video_data = message['video']
        
        if not video_data:
            return {"status": "ok, not a video submission"}

        existing_submission = (await db.execute(select(VideoSubmission).where(VideoSubmission.telegram_file_id == video_data['file_id']))).scalars().first()
        if existing_submission:
            logger.warning(f"Submission with telegram_file_id {video_data['file_id']} already exists. Skipping.")
            return {"status": "ok, duplicate submission"}

        volunteer = await get_or_create_volunteer(message['chat'], db)

        submission = VideoSubmission(
            telegram_file_id=video_data['file_id'],
            volunteer_id=volunteer.id,
            status=SubmissionStatus.PROCESSING
        )
        db.add(submission)
        await db.commit()
        await db.refresh(submission)

        file_path = await get_telegram_file_path(video_data['file_id'])
        file_name = video_data.get('file_name', f"{video_data['file_unique_id']}.mp4")
        local_dest = f"./temp_{file_name}"
        await download_telegram_file(file_path, local_dest)

        final_url = await upload_to_api_video(
            local_file_path=local_dest,
            video_title=f"Submission from {volunteer.username or volunteer.first_name}"
        )

        submission.video_platform_url = final_url
        submission.status = SubmissionStatus.PENDING_REVIEW
        await db.commit()
        
        logger.info(f"--- WEBHOOK COMPLETED SUCCESSFULLY for submission {submission.id} ---")
        return {"status": "ok"}

    except Exception as e:
        logger.error(f"--- FATAL ERROR in webhook processing: {type(e).__name__} - {e} ---", exc_info=True)
        await db.rollback()
        return {"status": "internal server error"}, 500

