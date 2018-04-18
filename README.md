# pwchecker

Exports a single function:

```go
CheckForPwnage(passwd string) (bool, string, string)
```

The function checks the password using the http://haveibeenpwned.com API and returns true if it has been seen
in the http://haveibeenpwned.com database.  It returns back the original passwd, and then returns the number of 
times the password has been pwned, with a default of 0 if it has not been pwned.
