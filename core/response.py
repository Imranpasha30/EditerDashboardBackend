from pydantic import BaseModel, Field
from typing import Generic,TypeVar,Optional , Any



T= TypeVar("T")


class IResponse(BaseModel,Generic[T]):
    """Standard API Response Model"""
    
    
    success: bool=Field(True,description="Indicates if the request was successful")
    message:Optional[str]=Field(None,description="A message providing addtional details about the response")
    data:Optional[T]=Field(None,description="The main payload of the response")
    
    
    @classmethod
    def success_response(cls,data:Optional[Any]=None, message:Optional[str] = "Request successful"):
        """Factory method to crtee a standardized sucess reposne"""
        return cls(sucess=True,message=message,data=data)
    
    
    @classmethod
    def error_response(cls,message:str):
        """Factory method to create a standardized error response """
        return cls(sucess=False,message=message,data=None)
    