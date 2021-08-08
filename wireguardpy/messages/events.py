"""
A file mimicking the events/state we'll see from the blockchain to mock out behavior.
"""
import pydantic


class Event(pydantic.BaseModel):
    pass


class ProviderEncryptedInfo(object):
    """
    This information is encrypted and put into the encrypted_info in the ProviderInfoSharing message below.
    """
    provider_ip_address: str
    user_ip_address: str
    vpn_pub_key: str

    class Config:
        schema_extra = {
            "example": {
                "provider_ip_address": "abc",
                "user_ip_address": "abc",
                "vpn_pub_key": "abc",
            }
        }


class EventProviderRegisterServer(Event):
    """
    Event for provider registering a server
    """
    account: str

    country: str
    rough_lat: float
    rough_long: float
    price_per_mb: int

    class Config:
        schema_extra = {
            "example": {
                "account": "abc",
                "country": "abc",
                "rough_lat": 123.456,
                "rough_long": 456.789,
                "price_per_mb": 10
            }
        }


class EventInit(Event):
    noop: str


class EventSendConnect(Event):
    """
    User sending connect event
    """
    program_id: str  # address of account data
    uid: int  # unique id


class EventRequestSent(Event):
    account: str  # users public key


class EventProviderConfiguration(Event):
    """
    The provider sharing the configuration for the user to setup their VPN with.
    """
    account: str
    account_to: str

    encrypted_info: bytes  # ProviderEncryptedInfo after decrypting
    encyption_pub_key: str

    class Config:
        schema_extra = {
            "example": {
                "account": "abc",
                "encrypted_info": b"1234",
                "encyption_pub_key": "foo"
            }
        }
