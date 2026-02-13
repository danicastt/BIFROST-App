using System.Security.Cryptography;
using System.Text;

namespace ProjekatZastita.Utils
{
    //KeyUtils klasa omogucava generisanje citljivog nasumicnog kljuca i derivaciju fiksne duzine kriptografskog kljuca iz korisnicke lozinke pomocu SHA-256 funkcije
    //time se obezbdjuje kompatibilnost sa algoritmima koji zahtevaju tacnu duzinu kljuca
    public static class KeyUtils
    {
        private const string ReadableChars =
            "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789"; //skup karaktera koji se koriste za generisanje kljuca
                                                                        // namerno su izbegnuti O i 0 i I i l kako bi se izbegla zabuna pri citanju

        /// pravi random (ljudima) citljiv kljuc
        public static string GenerateReadableKey(int length)
        {
            var sb = new StringBuilder(length);
            var rng = RandomNumberGenerator.Create(); //kriptografski siguran generator 
            byte[] buf = new byte[1];

            while (sb.Length < length)
            {
                rng.GetBytes(buf);
                int idx = buf[0] % ReadableChars.Length; //generisanje indeksa - uzima se slucajan bajt i mapira u opseg dozvoljenih karaktera
                sb.Append(ReadableChars[idx]);
            }

            return sb.ToString();
        }

        /// pravi kljuc fikse duzine iz kljuca koji je uneo korisnik, koristeci SHA-256
        public static byte[] DeriveKey(string password, int length)
        {
            byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(password));
            byte[] key  = new byte[length];
            Array.Copy(hash, key, Math.Min(length, hash.Length));
            return key;
        }
    }
}
