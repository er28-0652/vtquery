vtquery
===
`vtquery` is VirusTotal query library that doesn't use official API.  


## Usage
Query hash and get result from VirusTotal.
```go
hash := "909349d9beeaf08a155bdfc8aadf73d093e545b7"
vt := vtquery.NewDefaultClient()
result, err := vt.HashQuery(hash)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("%#v\n", result)
```