from pydantic import BaseModel, EmailStr, Field, ConfigDict
class RegisterIn(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    email: EmailStr
    password: str = Field(min_length=10, max_length=128)
class LoginIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)
class URLIn(BaseModel): url: str = Field(min_length=4, max_length=2048)
class EmailIn(BaseModel): content: str = Field(min_length=10, max_length=20000)
class NetworkIn(BaseModel): scope: str = Field(min_length=3, max_length=100)
class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int; email: str; name: str; role: str
