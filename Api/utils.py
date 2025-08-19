from datetime import datetime
import os
import random
import re
from django.core.mail import send_mail
import requests
import hashlib
import time
import base64
import hmac
from decouple import config
import string

from Movr import settings
from .models import OTP, CustomUser as User


def generate_unique_referral_code():
    """
    Generates a unique 8-character uppercase referral code.
    The code consists of letters and numbers, all in uppercase.
    """
    # Characters to use for referral code (uppercase letters and numbers)
    characters = string.ascii_uppercase + string.digits
    
    while True:
        # Generate a random 8-character code
        referral_code = ''.join(random.choice(characters) for _ in range(8))
        
        # Check if this code already exists in the database
        if not User.objects.filter(referral_code=referral_code).exists():
            return referral_code


# Generate OTP
def generate_otp():
    return str(random.randint(10000, 99999))


# Create OTP in the database
def create_otp(user):
    otp = generate_otp()
    otp_instance = OTP.objects.create(user=user, otp=otp)
    return otp_instance


# Send OTP via email
def send_otp_email(user, otp):
    subject = 'Your OTP for password reset'
    message = f'Your OTP to reset your password is: {otp}'
    send_mail(subject, message, settings.EMAIL_HOST_USER, [user.email])


def format_phone_number(phone_number: str) -> str:
    """
    Formats a phone number to E.164 standard (e.g., 2349024563447).
    Removes non-digits, leading zeros, and prepends '234' if needed.
    """
    phone_number = phone_number.strip()  # Remove spaces
    phone_number = re.sub(r"\D", "", phone_number)  # Remove non-digit characters

    # Remove leading 0 if it starts with 0 (e.g., "080..." -> "80...")
    if phone_number.startswith("0"):
        phone_number = phone_number[1:]

    # Ensure it starts with 234 (Nigeria's country code)
    if phone_number.startswith("234"):
        # Already starts with 234
        pass
    elif phone_number.startswith("+234"):
        # Remove the leading '+' (e.g., "+234..." -> "234...")
        phone_number = phone_number[1:]
    else:
        # If it's a local Nigerian number without the 234 prefix, prepend it.
        # This assumes numbers without 234 prefix are Nigerian.
        phone_number = "234" + phone_number

    return phone_number

def send_otp_sms(user, otp):
    """
    Sends an SMS message using the Termii API.

    Args:
        to_number (str): The recipient's phone number in international format (e.g., "2348012345678").
        message (str): The content of the SMS message.
        sender_id (str, optional): The sender ID for the message. Defaults to "Termii".
                                   You can register custom sender IDs on Termii.

    Returns:
        dict or None: A dictionary containing the API response on success, None on failure.
    """
    api_key = config('TERMII_LIVE_KEY')
    api_url = "https://v3.api.termii.com/api/sms/send"

    if not api_key:
        print("Termii API key not configured in settings.")
        return None

    headers = {
        "Content-Type": "application/json"
    }

    payload = {
        "to": user.phone_number,
        "from": 'Agba do',
        "sms": f'Your OTP to reset your password is: {otp}',
        "type": "plain",
        "channel": "generic",
        "api_key": api_key
    }

    try:
        response = requests.post(api_url, headers=headers, json=payload)
        response.raise_for_status()  # Raise an exception for HTTP errors (4xx or 5xx)
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error sending SMS via Termii: {e}")
        return None


def write_to_file(message, error=None):
    """
    Writes a message and an optional error to a file.
    
    :param file_path: Path to the file where logs will be written.
    :param message: The main message to write.
    :param error: (Optional) Error message to log.
    """
    try:
        with open("file.txt", "a") as file:
            file.write(f"Message: {message}\n")
            if error:
                file.write(f"Error: {error}\n")
            file.write("-" * 50 + "\n")  # Separator for readability
    except Exception as e:
        print(f"Failed to write to file: {e}")


def log_to_server(message, error=None, log_file_path="agbado.log"):
    """
    Logs a message (and optional error) to a log file.

    Args:
        message (str): The message to log.
        error (str, optional): Error message if applicable.
        log_file_path (str): Relative or absolute path to the log file.
    """
    log_dir = os.path.dirname(log_file_path)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir)

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        with open(log_file_path, "a") as log_file:
            log_file.write(f"[{timestamp}] MESSAGE: {message}\n")
            if error:
                log_file.write(f"[{timestamp}] ERROR: {error}\n")
            log_file.write("-" * 60 + "\n")
    except Exception as e:
        print(f"Failed to write to log file: {e}")


def upload_to_cloudinary(image_file):
    cloud_name = config("CLOUDINARY_CLOUD_NAME")
    api_key = config("CLOUDINARY_API_KEY")
    upload_preset = config("CLOUDINARY_UPLOAD_PRESET")

    upload_url = f"https://api.cloudinary.com/v1_1/{cloud_name}/image/upload"

    # Rewind in case it’s already been read
    image_file.seek(0)

    files = {
        "file": image_file,  # Don't use .read() — just pass the file object directly
    }

    data = {
        "api_key": api_key,
        "upload_preset": upload_preset,
    }

    response = requests.post(upload_url, files=files, data=data)
    print(f'{response.json()}')

    if response.status_code == 200:
        return response.json()["secure_url"]
    else:
        raise Exception(f"Cloudinary upload failed: {response.text}")
