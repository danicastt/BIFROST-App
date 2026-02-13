namespace ProjekatZastita.Crypto
{
    /// klasicna Bifid sifra radi nad slovima (5×5 tabela), ali ovde je prilagodjena za rad sa bajtovima, i to preko nibbles (4-bitne polovine bajta)
    /// umesto rada sa slovima, bajt (8 bitova) se deli na: gornjih 4 bita (high nibble) i donjih 4 bita (low nibble)
    /// posto nibble ima 16 mogucih vrednosti (0-15), koristi se matrica 4x4

    public class BifidCipher
    {
        // koristi se 4x4 matrica (ukupno 16 elemenata)
        private readonly int[,] _square = new int[4, 4];
        private readonly Dictionary<int, (int row, int col)> _coords = new();

        public BifidCipher(byte[] keyBytes)
        {
            // pravljenje permutovanog kvadrata
            var used = new bool[16];
            var order = new List<int>();

            foreach (byte b in keyBytes)
            {
                int nibble = b & 0x0F;
                if (!used[nibble]) { used[nibble] = true; order.Add(nibble); }
                nibble = (b >> 4) & 0x0F;
                if (!used[nibble]) { used[nibble] = true; order.Add(nibble); }
            }

            // dopuna preostalog
            for (int i = 0; i < 16; i++)
                if (!used[i]) order.Add(i);

            for (int i = 0; i < 16; i++)
            {
                int r = i / 4, c = i % 4;
                _square[r, c] = order[i];
                _coords[order[i]] = (r, c);
            }
        }

        /// ulazni bitovi se frakcionisu, kombinuju a zatim opet grupisu
        /// radi nad blokovima parne duzine, neparni bajt se propusta xor operacijom
        public byte[] Encrypt(byte[] data)
        {
            // deli svaki bajt na 2 nibble
            var nibbles = new List<int>(data.Length * 2);
            foreach (byte b in data)
            {
                nibbles.Add((b >> 4) & 0x0F);
                nibbles.Add(b & 0x0F);
            }

            int n = nibbles.Count;
            var rows = new int[n];
            var cols = new int[n];

            for (int i = 0; i < n; i++)
            {
                var (r, c) = _coords[nibbles[i]];
                rows[i] = r;
                cols[i] = c;
            }

            // mesanje redova i kolona
            var combined = rows.Concat(cols).ToArray();

            // ucitavanje po parovima
            var result = new byte[data.Length];
            for (int i = 0; i < data.Length; i++)
            {
                int idx = i * 2;
                int high = _square[combined[idx], combined[idx + 1]];
                int low = (idx + 2 < combined.Length)
                    ? _square[combined[idx + 2], combined[idx + 3]]
                    : nibbles[i * 2 + 1];
                result[i] = (byte)((high << 4) | low);
            }

            return result;
        }

        public byte[] Decrypt(byte[] data)
        {
            // isto frakcionisanje, ali obrnuti korak mesanja
            var nibbles = new List<int>(data.Length * 2);
            foreach (byte b in data)
            {
                nibbles.Add((b >> 4) & 0x0F);
                nibbles.Add(b & 0x0F);
            }

            int n = nibbles.Count;
            // combined = rows[0..n-1] + cols[0..n-1]
            var combined = new int[n * 2];
            for (int i = 0; i < n; i++)
            {
                var (r, c) = _coords[nibbles[i]];
                combined[i] = r;
                combined[n + i] = c;
            }

            var result = new byte[data.Length];
            for (int i = 0; i < data.Length; i++)
            {
                int rIdx = i * 2;
                int cIdx = i * 2;
                int high = _square[combined[rIdx], combined[n + cIdx]];
                int low = (rIdx + 1 < n)
                    ? _square[combined[rIdx + 1], combined[n + cIdx + 1]]
                    : nibbles[i * 2 + 1];
                result[i] = (byte)((high << 4) | low);
            }

            return result;
        }
    }
}
