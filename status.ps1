$ErrorActionPreference = 'Stop'

$status = @{ }

$listener = [System.Net.HttpListener]::new()
$listener.Prefixes.Add('http://+:80/')
$listener.Start()

while (1) {
    $context = $listener.GetContext()
    $request = $context.Request
    $path = $request.Url.AbsolutePath
    $method = $request.HttpMethod

    if ($path -in '/quit', '/exit') {
        $context.Response.OutputStream.Close()
        $listener.Stop()
        break
    } elseif ($path -in '/status', '/s') {
        if ($method -eq 'POST') {
            try {
                $data = [System.IO.StreamReader]::new($request.InputStream).ReadToEnd() | ConvertFrom-Json
                $status[$data.IP] = [PSCustomObject]@{
                    Host    = $data.Host
                    Message = $data.Message
                    Time    = [datetime]::Now.ToString('yyyy-MM-dd HH:mm:ss')
                }
            } catch {
                $context.Response.StatusCode = 400
                $context.Response.StatusDescription = 'bad request'
            } finally {
                $context.Response.OutputStream.Close()
            }
        } else {
            $data = @( )
            $data += foreach ($ip in $status.Keys) {
                [PSCustomObject]@{
                    IP      = $ip
                    Host    = $status.$ip.Host
                    Message = $status.$ip.Message
                    Time    = $status.$ip.Time
                }
            }
            $json = ConvertTo-Json -InputObject $data
            $response = $context.Response
            $response.ContentType = 'application/json'
            [byte[]]$buffer = [System.Text.Encoding]::UTF8.GetBytes($json)
            $response.ContentLength64 = $buffer.Length
            $response.OutputStream.Write($buffer, 0, $buffer.Length)
            $response.OutputStream.Close()
        }
    } else {
        $data = @( )
        $data += foreach ($ip in $status.Keys) {
            [PSCustomObject]@{
                IP      = $ip
                Host    = $status.$ip.Host
                Message = $status.$ip.Message
                Time    = $status.$ip.Time
            }
        }
        if ($data.Count -gt 0) {
            $html = $data | Sort-Object -Property Time | ConvertTo-Html -Title Status -As Table
        } else {
            $html = ConvertTo-Html -Title Status -As Table
        }
        $response = $context.Response
        $response.ContentType = 'text/html'
        [byte[]]$buffer = [System.Text.Encoding]::UTF8.GetBytes($html)
        $response.ContentLength64 = $buffer.Length
        $response.OutputStream.Write($buffer, 0, $buffer.Length)
        $response.OutputStream.Close()
    }
}
