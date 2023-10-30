package main

import "fmt"

func main() {
	arr1 := []int{1, 2, 3}
	arr2 := arr1[1:2]
	arr2[0] = 6
	copy(arr1, arr2)
	fmt.Println(arr1)
	fmt.Println(arr2)

}
