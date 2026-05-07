namespace ServiSeg.Auth
{
    public class AuthResult
    {
        public bool Result { get; set; }
        public List<String> Errors { get; set; }
        public string Token { get; set; }
    }
}
