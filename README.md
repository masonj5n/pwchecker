# pwchecker

Exports a single function:

```go
func CheckForPwnage(pw string) (*Pwd, error)
```

The function checks the password using the http://haveibeenpwned.com API.

It returns a pointer to a struct like so:

```go
type Pwd struct {
	Pwnd   bool
	Pwd    string
	TmPwnd string
}
```

`Pwnd` is true if the password has been pwned. <br>
`Pwd` is the original password passed to the fucntion. <br>
`TmPwnd` is a string with the number of times the password has been pwned.
