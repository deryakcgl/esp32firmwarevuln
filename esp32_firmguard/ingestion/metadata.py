import hashlib
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class FirmwareMetadata:
    """Metadata about a firmware file"""
    name: str
    size: int
    source: str
    md5_hash: str
    sha256_hash: str
    architecture: Optional[str] = None
    endianness: Optional[str] = None
    bitness: Optional[int] = None


def extract_metadata(firmware_path: Path, source: str = "unknown") -> FirmwareMetadata:
    """
    Extract metadata from a firmware file.
    
    Args:
        firmware_path: Path to firmware binary
        source: Source of the firmware (e.g., "tasmota", "esp-idf", "custom")
    
    Returns:
        FirmwareMetadata object with file information
    """
    firmware_path = Path(firmware_path)
    
    if not firmware_path.exists():
        raise FileNotFoundError(f"Firmware not found: {firmware_path}")
    
    # Read file for hashing
    with open(firmware_path, 'rb') as f:
        data = f.read()
    
    # Calculate hashes
    md5_hash = hashlib.md5(data).hexdigest()
    sha256_hash = hashlib.sha256(data).hexdigest()
    
    # Get file size
    file_size = len(data)
    
    # Try to detect architecture from file content or name
    architecture = _detect_architecture(firmware_path, data)
    endianness = "little"  # ESP32 is little-endian
    bitness = 32  # ESP32 is 32-bit
    
    metadata = FirmwareMetadata(
        name=firmware_path.name,
        size=file_size,
        source=source,
        md5_hash=md5_hash,
        sha256_hash=sha256_hash,
        architecture=architecture,
        endianness=endianness,
        bitness=bitness
    )
    
    
    return metadata


def _detect_architecture(firmware_path: Path, data: bytes) -> Optional[str]:
    """Try to detect architecture from file content or name"""
    # Check for ESP32/Xtensa signatures
    # ESP32 firmware often has specific magic bytes or patterns
    if len(data) > 0:
        # Check for common ESP32 patterns
        if b"ESP32" in data[:1024] or b"Xtensa" in data[:1024]:
            return "xtensa"
        
        # Check file extension or name patterns
        name_lower = firmware_path.name.lower()
        if "esp32" in name_lower or "xtensa" in name_lower:
            return "xtensa"
        
        # Default to xtensa for ESP32 firmware
        return "xtensa"
    
    return None

