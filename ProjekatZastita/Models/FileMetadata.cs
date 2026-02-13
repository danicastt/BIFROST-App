using System.Text.Json.Serialization;

namespace ProjekatZastita.Models
{
    /// Metadata header je sacuvan na pocetku svakog enkriptovanog fajla (hash je u zaglavlju)
    ///svaki enkriptovani fajl sadrzi JSON metapodatke na pocetku, koji opisuju algoritam, rezim rada, hash funkciju, originalnu velicinu i ime fajla
    /// ovi podaci se serijalizuju i prefiksiraju duzinom(4-byte little-endian int), cime je omoguceno pravilno parsiranje i dekripcija bez spoljašnjih informacija
    public class FileMetadata
    {
        [JsonPropertyName("filename")]
        public string FileName { get; set; } = string.Empty;//filename - originalno ime fajla bez enkripcije - omogucava da se nakon dekripcije fajl vrati pod istim imenom

        [JsonPropertyName("original_extension")]
        public string OriginalExtension { get; set; } = string.Empty; //OriginalExtension - ekstenzija fajl (.txt, .jpg)-zato sto enkriptovani fajl ima verovatno .enc

        [JsonPropertyName("filesize")]
        public long FileSize { get; set; } //FileSize -originalna velicina fajla pre enkripcije - moze se koristiti za proveru integriteta, validaciju dekripcije

        [JsonPropertyName("created")]
        public DateTime CreatedDate { get; set; } //SreatedDate - kada je fajl originalno napravljen

        [JsonPropertyName("encrypted")]
        public DateTime EncryptedDate { get; set; } //EncryptedDate -kada je izvrsena enkripcija

        [JsonPropertyName("algorithm")]
        public string Algorithm { get; set; } = string.Empty; //koji alg je koriscen - omogucava sistemu da zna kako da ga dekriptuje

        [JsonPropertyName("mode")]
        public string Mode { get; set; } = "OFB"; // rezim rada (podrazumevano OFB)

        [JsonPropertyName("hash_algorithm")]
        public string HashAlgorithm { get; set; } = "SHA1";

        [JsonPropertyName("hash")]
        public string Hash { get; set; } = string.Empty; //hesh originalnog fajla, koristi se za proveru integriteta i validaciju dekripcije

        [JsonPropertyName("mime_type")]
        public string MimeType { get; set; } = string.Empty; //tip fajla, npr image/jpeg...

        [JsonPropertyName("chunk_size")]
        public int ChunkSize { get; set; } = 65536; //velicina bloka za obradu fajla (ovde npr 64KB) - bitno za stream obradu velikih fajlova

        [JsonPropertyName("version")]
        public string Version { get; set; } = "2.0"; //verzija formata metapodataka
    }
}
    //bez ovog zaglavlja sistem ne bi znao koji alg da koristi, ne bi znao hash, ne bi znao kako da vrati ime fajla, ne bi znao verziju formata 
    //omogucava samostalnu dekripciju fajla