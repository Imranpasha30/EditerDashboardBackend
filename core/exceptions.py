from fastapi import status


class APIException(Exception):
    """
    Base class for custom API exceptions. 
    Aloow for a status code and details message.
    """
    
    def __init__(self,status_code:int,detail:str):
        self.status_code=status_code
        self.detail=detail
        super().__init__(self.detail)
        
#---Specific HTTP Exception ----


class NotFoundException(APIException):
    """
    To be raised when a requested response is not found Results in a 404 found response."""
    
    def __init__(self,detail:str="Resource not found"):
        super().__init__(status_code=status.HTTP_404_NOT_FOUND,detail=detail)
        
        
class BadRequestException(APIException):
    """
    To be raised when a bad request is made. Results in a 400 Bad Request response.
    """
    
    def __init__(self,detail:str="Bad request"):
        super().__init__(status_code=status.HTTP_400_BAD_REQUEST,detail=detail)
        
class UnauthorizedException(APIException):
    """
    To be raised when authentication fails or is missing. Results in a 401 Unauthorized response.
    """
    
    def __init__(self,detail:str="Unauthorized"):
        super().__init__(status_code=status.HTTP_401_UNAUTHORIZED,detail=detail)
        

class ForbiddenException(APIException):
    """
    To be raised when the user does not have permission to access a resource. Results in a 403 Forbidden response.
    """
    
    def __init__(self,detail:str="Forbidden"):
        super().__init__(status_code=status.HTTP_403_FORBIDDEN,detail=detail)
        
class ConflictException(APIException):
    """
    To be raised when a conflict occurs, such as a duplicate resource. Results in a 409 Conflict response.
    """
    
    def __init__(self,detail:str="Conflict"):
        super().__init__(status_code=status.HTTP_409_CONFLICT,detail=detail)
        
class InternalServerErrorException(APIException):
    """
    To be raised when an unexpected error occurs on the server. Results in a 500 Internal Server Error response.
    """
    
    def __init__(self,detail:str="Internal server error"):
        super().__init__(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,detail=detail)

