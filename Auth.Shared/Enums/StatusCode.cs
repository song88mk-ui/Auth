namespace Auth.Shared.Enums
{
    public enum StatusCode
    {
        Success = 100,
        Invalid_Password = 201,
        Username_Not_Found = 202,
        Record_Is_Already_Existing = 203,
        User_Is_Locked = 204,
        Unauthorized = 401,
        Error = 1000
    }
}
