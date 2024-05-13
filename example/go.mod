module example

go 1.21.3

//import cgo.go from ../cgo/cgo.go in go mod

require github.com/aeriuslabs/ezkl-ffi v0.0.0

replace github.com/aeriuslabs/ezkl-ffi v0.0.0 => ../
