# BubbleSort Algorithm
# EDX-Course : DEV204.3 Algorithms and Datastructures in C#

$nums = @(5,10,3,2,4)

write-host "Values before sort : $nums"

do {

    $swapped = $false

    # Loop over array of values
    for($i = 0;$i -lt $nums.length-1; $i++)
    {
        if($nums[$i] -gt $nums[$i+1])
        {
            # Swap values with help of temp variable
            $temp = $nums[$i+1]
            $nums[$i+1] = $nums[$i]
            $nums[$i] = $temp

            # Indicate a swap activity which means we need an additional run
            $swapped = $true
        }
    }
} while($swapped -eq $true)

# Show Result
write-host "Values after Sort : $nums"