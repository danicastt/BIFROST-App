using System.Security.Cryptography;

namespace ProjekatZastita.Crypto
{
    /// posto aplikacija omogucava slanje fajlova putem TCP protokola, bilo je potrebno obezbediti mehanizam za proveru integriteta podataka nakon prenosa
    /// u tu svrhu implementirana je SHA-1 hes funkcija, koja se primenjuje nad originalnim podacima pre slanja i nakon prijema
    /// cime se proverava da li je doslo do izmene ili ostecenja podataka tokom prenosa ili dekripcije
    public static class SHA1Helper
    {
        public static string ComputeHash(byte[] data)
        {
            byte[] hash = SHA1.HashData(data); //.net metoda direktno racuna SHA-1 bez rucnog kreiranja objekta
            return Convert.ToHexString(hash).ToLowerInvariant(); //hash bajt se pretvara u string, kako bi format bio konzistentan
        }

        /// SHA-1 direktno radi nad strimom, kako ne bi ucitavali cao fajl u memoriju (koristi se kod velikih fajlova)
        public static string ComputeHash(Stream stream)
        {
            using var sha = SHA1.Create();
            byte[] hash = sha.ComputeHash(stream);
            return Convert.ToHexString(hash).ToLowerInvariant();
        }
    }
}
