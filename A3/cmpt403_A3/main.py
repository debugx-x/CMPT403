def string_matching(s, t):
    n = len(s)
    m = len(t)

    # Create a dp array of size (n+1) to store the results of subproblems
    dp = [0] * (n + 1)
    dp[0] = True  # An empty string can be formed with no substrings

    # Iterate through the binary string 's'
    for i in range(1, n + 1):
        for j in range(1, m + 1):
            # Check if the substring ending at position 'i' matches any of the 't' strings
            if i >= len(t[j - 1]) and s[i - len(t[j - 1]):i] == t[j - 1]:
                dp[i] = dp[i] or dp[i - len(t[j - 1])]

    # Reconstruct the representation of 's' if it can be expressed as a concatenation of 't' strings
    if dp[n]:
        result = []
        i = n
        while i > 0:
            for j in range(1, m + 1):
                if i >= len(t[j - 1]) and s[i - len(t[j - 1]):i] == t[j - 1] and dp[i] and dp[i - len(t[j - 1])]:
                    result.append(j)
                    i -= len(t[j - 1])
                    break
        result.reverse()
        return "YES", result
    else:
        return "NO", None


# Example usage
n = 8
m = 3
s = "01110101"
t = ["000", "01", "11"]

result, representation = string_matching(s, t)
print("Answer:", result)
if representation:
    print("Representation:", representation)
