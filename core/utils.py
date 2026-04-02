import requests
from decouple import config


def upload_to_cloudinary(image_file):
    """
    Uploads an image file to Cloudinary and returns the secure URL.
    
    Args:
        image_file: The image file to upload (file object)
        
    Returns:
        str: The secure URL of the uploaded image
        
    Raises:
        Exception: If the upload fails
    """
    cloud_name = config("CLOUDINARY_CLOUD_NAME")
    api_key = config("CLOUDINARY_API_KEY")
    upload_preset = config("CLOUDINARY_UPLOAD_PRESET")

    upload_url = f"https://api.cloudinary.com/v1_1/{cloud_name}/image/upload"

    image_file.seek(0)

    files = {
        "file": image_file,
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