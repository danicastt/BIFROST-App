namespace ProjekatZastita.Crypto
{
    public interface IStreamCipher
    {
        /// XOR transformacija broji bajtove u baferu pocevsi od offset-a
        void Transform(byte[] buffer, int offset, int count);
    }

    /// Bifid-OFB stream cipher:
    /// korsti RC6-OFB da generise pseudorandom keystream,
    /// zatim mpdifikuje svaki keystream bajt koristeci Bifid substituciju pre XOR-ovanja sa plaintext-om
    /// ovo kombinuje Bifid frakcionisanje sa dodatnom bezbednoscu koriscenjem OFB generatora kljuceva
    public sealed class BifidOFBStreamCipher : IStreamCipher
    {
        private readonly RC6OFBStreamCipher _rc6;
        private readonly BifidCipher _bifid;

        public BifidOFBStreamCipher(byte[] key)
        {
            _rc6   = new RC6OFBStreamCipher(key);
            _bifid = new BifidCipher(key);
        }

        public void Transform(byte[] buffer, int offset, int count)
        {
            // 1. generisanje RC6-OFB keystream-a u privremeni bafer
            byte[] keystream = new byte[count];
            Array.Fill<byte>(keystream, 0);  //popunjuje se nulama
            _rc6.Transform(keystream, 0, count); //  zato sto 0 ^ keystreamByte = keystreamByte (dobijamo cist keystream)

            // 2. Scramble keystream dobijen dodatnom Bidif permutacijom
            byte[] scrambled = _bifid.Encrypt(keystream);

            // 3. XOR nad podacima 
            // enkripcija: cipherByte = plainByte XOR scrambledKeystreamByte
            //dekripcija: plainByte = cipherByte XOR scrambledKeystreamByte
            for (int i = 0; i < count; i++)
                buffer[offset + i] ^= scrambled[i];
        }
    }
}
