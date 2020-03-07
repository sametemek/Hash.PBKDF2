namespace Hash.PBKDF2
{
    public interface IHasher
    {
        string Hash(string word, string salt = null);
        bool Validate(string word, string salt, string hash);
    }
}