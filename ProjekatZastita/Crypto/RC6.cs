namespace ProjekatZastita.Crypto
{
    /// RC6 blok-sifrator (32-bitova,  20 rundi, promenljiva duzina kljuca)
    /// koristi 128-bitni kljuc (16 bajtova). Velicina bloka takodje 128 bita
    public class RC6
    {
        private const int W = 32;           // 4 reci od po 32b (A,B,C,D)
        private const int R = 20;           // rundi
        private const int W_BYTES = W / 8;  // 4 reci

        private readonly uint[] _S;         // _S= key schedule: 2*(R+2) = 44 reci (to su zapravo podkljucevi generisani iz glavnog kljuca)

        private static uint RotL(uint x, int n) => (x << n) | (x >> (W - n));  // ne radi se shift jer bi izgubili podatke, kod rotacije se podaci ne gube
        private static uint RotR(uint x, int n) => (x >> n) | (x << (W - n));
        private static int LgW => 5; // log2(32) = 5

        public RC6(byte[] key)
        {
            if (key.Length != 16)
                throw new ArgumentException("RC6 kljuc mora biti 128-bitni (16 bajtova)!");
            _S = KeySchedule(key);
        }

        private static uint[] KeySchedule(byte[] key)
        {
            const uint P32 = 0xB7E15163;
            const uint Q32 = 0x9E3779B9;

            int u = W_BYTES;
            int b = key.Length;
            int c = (b + u - 1) / u;

            var L = new uint[c]; //kljuc se deli na 32-bitne blokove
            for (int i = b - 1; i >= 0; i--)
                L[i / u] = (L[i / u] << 8) + key[i];

            int t = 2 * (R + 2);
            var S = new uint[t];
            S[0] = P32;
            for (int i = 1; i < t; i++)
                S[i] = unchecked(S[i - 1] + Q32);

            uint A = 0, B = 0;
            int iA = 0, iB = 0;
            int n = 3 * Math.Max(t, c);

            for (int s = 0; s < n; s++)  //ovde se kombinuju podkljucevi, originalni kljuc, sabiranje, rotacije
            {
                A = S[iA] = RotL(unchecked(S[iA] + A + B), 3);
                B = L[iB] = RotL(unchecked(L[iB] + A + B), (int)((A + B) & 31));
                iA = (iA + 1) % t;
                iB = (iB + 1) % c;
            }

            return S;
        }

        /// blok od 16 bajtova se deli na A, B, C , D
        public void EncryptBlock(byte[] block, int offset = 0)
        {
            uint A = BitConverter.ToUInt32(block, offset);
            uint B = BitConverter.ToUInt32(block, offset + 4);
            uint C = BitConverter.ToUInt32(block, offset + 8);
            uint D = BitConverter.ToUInt32(block, offset + 12);

            B = unchecked(B + _S[0]); //dodavanje pocetnih potkljuceva
            D = unchecked(D + _S[1]);

            for (int i = 1; i <= R; i++)
            { 
                //ovo se racuna za svaku rundu
                uint t = RotL(unchecked(B * (2 * B + 1)), LgW);
                uint u = RotL(unchecked(D * (2 * D + 1)), LgW);
                A = unchecked(RotL(A ^ t, (int)(u & 31)) + _S[2 * i]);
                C = unchecked(RotL(C ^ u, (int)(t & 31)) + _S[2 * i + 1]);
                uint tmp = A; A = B; B = C; C = D; D = tmp;
            }

            A = unchecked(A + _S[2 * R + 2]);
            C = unchecked(C + _S[2 * R + 3]);

            WriteUInt32(block, offset,      A);
            WriteUInt32(block, offset + 4,  B);
            WriteUInt32(block, offset + 8,  C);
            WriteUInt32(block, offset + 12, D);
        }

        /// dekripcija radi potpuno obrnuti proces: oduzimanje potkljuceva, obrnute rotacije, inverzna zamena registara
        public void DecryptBlock(byte[] block, int offset = 0)
        {
            uint A = BitConverter.ToUInt32(block, offset);
            uint B = BitConverter.ToUInt32(block, offset + 4);
            uint C = BitConverter.ToUInt32(block, offset + 8);
            uint D = BitConverter.ToUInt32(block, offset + 12);

            C = unchecked(C - _S[2 * R + 3]);
            A = unchecked(A - _S[2 * R + 2]);

            for (int i = R; i >= 1; i--)
            {
                uint tmp = D; D = C; C = B; B = A; A = tmp;
                uint u = RotL(unchecked(D * (2 * D + 1)), LgW);
                uint t = RotL(unchecked(B * (2 * B + 1)), LgW);
                C = unchecked(RotR(C - _S[2 * i + 1], (int)(t & 31)) ^ u);
                A = unchecked(RotR(A - _S[2 * i],     (int)(u & 31)) ^ t);
            }

            D = unchecked(D - _S[1]);
            B = unchecked(B - _S[0]);

            WriteUInt32(block, offset,      A);
            WriteUInt32(block, offset + 4,  B);
            WriteUInt32(block, offset + 8,  C);
            WriteUInt32(block, offset + 12, D);
        }

        private static void WriteUInt32(byte[] buf, int off, uint val)
        {
            var bytes = BitConverter.GetBytes(val);
            buf[off]     = bytes[0];
            buf[off + 1] = bytes[1];
            buf[off + 2] = bytes[2];
            buf[off + 3] = bytes[3];
        }

        // OFB REZIM
        // RC6 je blok-sifrator; koristimo OFB kako bismo dobili keystream (tj mogli da radimo sa podacima proizvoljne duzine)
        /// na kraju se keystream XOR-uje sa podacima, cime se dobija simetricna enkripcija/dekripcija
        /// IV je izveden iz kljuca (prvih 16 bajtova)

        public byte[] EncryptOFB(byte[] data)
        {
            const int BlockSize = 16;
            byte[] result = new byte[data.Length];

            // IV = prvih 16 bajtova kljuca
            byte[] feedback = new byte[BlockSize];
            Array.Copy(_S.Take(4).SelectMany(BitConverter.GetBytes).ToArray(), feedback, BlockSize);

            int pos = BlockSize;
            byte[] keystreamBlock = new byte[BlockSize];

            for (int i = 0; i < data.Length; i++)
            {
                if (pos == BlockSize)
                {
                    Array.Copy(feedback, keystreamBlock, BlockSize);
                    EncryptBlock(keystreamBlock);
                    Array.Copy(keystreamBlock, feedback, BlockSize);
                    pos = 0;
                }
                result[i] = (byte)(data[i] ^ keystreamBlock[pos++]);
            }

            return result;
        }

        public byte[] DecryptOFB(byte[] data) => EncryptOFB(data); // OFB je simetrican
    }

    /// implementacija interfejsa IStreamCipher
    public sealed class RC6OFBStreamCipher : IStreamCipher
    {
        private readonly RC6 _rc6;
        private readonly byte[] _feedback = new byte[16];
        private readonly byte[] _keystreamBlock = new byte[16];
        private int _pos;

        public RC6OFBStreamCipher(byte[] key)
        {
            _rc6 = new RC6(key);
            var sBytes = new uint[] {
                (uint)((key[0]<<24)|(key[1]<<16)|(key[2]<<8)|key[3]),
                (uint)((key[4]<<24)|(key[5]<<16)|(key[6]<<8)|key[7]),
                (uint)((key[8]<<24)|(key[9]<<16)|(key[10]<<8)|key[11]),
                (uint)((key[12]<<24)|(key[13]<<16)|(key[14]<<8)|key[15]),
            };
            int off = 0;
            foreach (var u in sBytes)
            {
                var b = BitConverter.GetBytes(u);
                Array.Copy(b, 0, _feedback, off, 4);
                off += 4;
            }
            _pos = 16;
        }

        public void Transform(byte[] buffer, int offset, int count)
        {
            for (int i = 0; i < count; i++)
            {
                if (_pos == 16)
                {
                    Array.Copy(_feedback, _keystreamBlock, 16);
                    _rc6.EncryptBlock(_keystreamBlock);
                    Array.Copy(_keystreamBlock, _feedback, 16);
                    _pos = 0;
                }
                buffer[offset + i] ^= _keystreamBlock[_pos++];
            }
        }
    }
}
