import httpx
import logging
from core.config import settings
from typing import Optional

logger = logging.getLogger(__name__)

class TelegramService:
    
    @staticmethod
    async def send_message(chat_id: str, message: str) -> bool:
        """
        Send a message to a Telegram user via bot
        
        Args:
            chat_id: Telegram chat ID (volunteer_id in our case)
            message: Message text to send
            
        Returns:
            bool: True if message sent successfully, False otherwise
        """
        try:
            if not settings.TELEGRAM_BOT_TOKEN:
                logger.error("TELEGRAM_BOT_TOKEN not configured")
                return False
            
            if not chat_id:
                logger.error("No chat_id provided for Telegram message")
                return False
            
            url = f"https://api.telegram.org/bot{settings.TELEGRAM_BOT_TOKEN}/sendMessage"
            
            payload = {
                "chat_id": chat_id,
                "text": message,
                "parse_mode": "HTML",  # Allows HTML formatting
                "disable_web_page_preview": False  # Enable preview for video URLs
            }
            
            logger.info(f"📱 Sending Telegram message to chat_id: {chat_id}")
            logger.debug(f"Message content: {message}")
            
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(url, json=payload)
                
                if response.status_code == 200:
                    result = response.json()
                    if result.get("ok"):
                        logger.info(f"✅ Telegram message sent successfully to {chat_id}")
                        return True
                    else:
                        logger.error(f"❌ Telegram API error: {result.get('description', 'Unknown error')}")
                        return False
                else:
                    logger.error(f"❌ Telegram HTTP error: {response.status_code} - {response.text}")
                    return False
                    
        except httpx.TimeoutException:
            logger.error(f"⏰ Timeout sending Telegram message to {chat_id}")
            return False
        except Exception as e:
            logger.error(f"💥 Error sending Telegram message to {chat_id}: {str(e)}", exc_info=True)
            return False
    
    @staticmethod
    async def send_video_declined_notification(
        chat_id: str, 
        decline_reason: str, 
        video_url: str,
        volunteer_name: Optional[str] = None
    ) -> bool:
        """
        Send a video decline notification to volunteer with video URL
        
        Args:
            chat_id: Volunteer's Telegram chat ID
            decline_reason: Reason for declining the video
            video_url: URL of the declined video
            volunteer_name: Optional volunteer name for personalization
            
        Returns:
            bool: True if notification sent successfully
        """
        try:
            name_part = f"Hi {volunteer_name}!\n\n" if volunteer_name else "Hi!\n\n"
            
            # Format video URL nicely
            video_link = f'<a href="{video_url}">🎬 View Your Video</a>' if video_url else "Your video"
            
            message = f"""{name_part}🚫 <b>Video Submission Declined</b>

Unfortunately, your recent video submission has been declined by our review team.

<b>🎥 Declined Video:</b>
{video_link}

<b>📝 Reason:</b>
{decline_reason}

<b>💡 What's Next?</b>
• Review our content guidelines
• Feel free to submit another video that meets our requirements
• Contact support if you have any questions

Thank you for your contribution and understanding! 🙏

<i>- Editorial Team</i>"""

            return await TelegramService.send_message(chat_id, message)
            
        except Exception as e:
            logger.error(f"💥 Error creating decline notification for {chat_id}: {str(e)}")
            return False

    
    @staticmethod
    async def send_video_completion_notification(
        chat_id: str, 
        original_video_url: str,
        completed_video_url: str,
        volunteer_name: Optional[str] = None,
        editor_notes: Optional[str] = None
    ) -> bool:
        """
        Send a video completion success notification to volunteer
        
        Args:
            chat_id: Volunteer's Telegram chat ID
            original_video_url: URL of their original submitted video
            completed_video_url: URL where their video was used/published
            volunteer_name: Optional volunteer name for personalization
            editor_notes: Optional notes from the editor
            
        Returns:
            bool: True if notification sent successfully
        """
        try:
            name_part = f"Hi {volunteer_name}!\n\n" if volunteer_name else "Hi!\n\n"
            
            # Format video URLs nicely
            original_link = f'<a href="{original_video_url}">🎥 Your Original Video</a>' if original_video_url else "Your original video"
            completed_link = f'<a href="{completed_video_url}">🎬 Published Video</a>' if completed_video_url else "Published video"
            
            # Add editor notes if provided
            editor_notes_part = f"\n<b>📝 Editor Notes:</b>\n{editor_notes}\n" if editor_notes else ""
            
            message = f"""{name_part}🎉 <b>Your Video Has Been Published!</b>

    Great news! Your video submission has been successfully edited and published on our channel.

    <b>🎥 Your Original Submission:</b>
    {original_link}

    <b>🎬 Published Video:</b>
    {completed_link}{editor_notes_part}

    <b>🙏 Thank You!</b>
    Your contribution helps make our content better. We appreciate your effort and creativity!

    <b>💡 What's Next?</b>
    • Check out the published video and share it with friends
    • Submit more videos to continue contributing
    • Follow our channel for more content

    Keep creating amazing content! 🚀

    <i>- Editorial Team</i>"""

            return await TelegramService.send_message(chat_id, message)
            
        except Exception as e:
            logger.error(f"💥 Error creating completion notification for {chat_id}: {str(e)}")
            return False
