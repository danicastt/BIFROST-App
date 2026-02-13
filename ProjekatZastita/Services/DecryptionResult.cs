using ProjekatZastita.Models;

namespace ProjekatZastita.Services
{
    public class DecryptionResult
    {
        //DecryptionResult je klasa koja enkapsulira rezultat dekripcije, ukljucujuci metapodatke fajla, putanju izlaznog fajla i rezultat provere integriteta
        //time je omogucen cist povratni tip bez koriscenja globalnih promenljivih ili dodatnih parametara
        //Metadata moze biti nullable jer u slucaju da parsiranje zaglavlja ne uspe ili je fajl ostecen, dekripcija moze da se izvrsi bez validnih metapodataka

        public FileMetadata? Metadata   { get; }
        public string        OutputPath { get; } //putanja gde je dekriptovani fajl sacuvan
        public bool          HashValid  { get; } //ako je false -doslo je do greske ili je fajl kompromitovan

        public DecryptionResult(FileMetadata? metadata, string outputPath, bool hashValid)
        {
            Metadata   = metadata;
            OutputPath = outputPath;
            HashValid  = hashValid;
        }
    }
}
