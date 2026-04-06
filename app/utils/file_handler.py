import aiofiles
import os
import shutil
from fastapi import UploadFile
from typing import List
import uuid
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class FileHandler:
    def __init__(self, upload_dir: Path = Path("uploads")):
        self.upload_dir = upload_dir
        self.upload_dir.mkdir(parents=True, exist_ok=True)

    async def save_upload_file(self, file: UploadFile) -> Path:
        """Save a single uploaded file"""
        # Generate unique filename
        file_extension = Path(file.filename).suffix if file.filename else ".apk"
        unique_filename = f"{uuid.uuid4().hex}{file_extension}"
        file_path = self.upload_dir / unique_filename

        try:
            content = await file.read()
            async with aiofiles.open(file_path, 'wb') as out_file:
                await out_file.write(content)

            logger.info(f"File saved: {file_path}")
            return file_path

        except Exception as e:
            logger.error(f"Error saving file: {e}")
            raise
        finally:
            await file.close()

    async def save_multiple_files(self, files: List[UploadFile]) -> List[Path]:
        """Save multiple uploaded files"""
        file_paths = []

        for file in files:
            try:
                file_path = await self.save_upload_file(file)
                file_paths.append(file_path)
            except Exception as e:
                logger.error(f"Error saving file {file.filename}: {e}")
                # Clean up already saved files
                for saved_path in file_paths:
                    await self.cleanup_file(saved_path)
                raise

        return file_paths

    async def cleanup_file(self, file_path: Path):
        """Remove a file"""
        try:
            if file_path.exists():
                file_path.unlink()
                logger.info(f"Cleaned up: {file_path}")
        except Exception as e:
            logger.error(f"Error cleaning up {file_path}: {e}")

    async def cleanup_multiple_files(self, file_paths: List[Path]):
        """Remove multiple files"""
        for file_path in file_paths:
            await self.cleanup_file(file_path)