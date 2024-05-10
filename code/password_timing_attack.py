import time
import statistics
import string
from password_check import check_password

PLOT = True

if PLOT:
    import matplotlib.pyplot as plt

# count the number of password attempts we did
TOTAL_ATTEMPTS = 0

# measure execution time of check_password(user_input) in nanoseconds
def time_input(user_input):
    global TOTAL_ATTEMPTS
    TOTAL_ATTEMPTS += 1
    start = time.time_ns()
    check_password(user_input)
    return time.time_ns() - start

# scatter plot of given y values with a label for each value
def scatter_plot(y, labels):
    if not PLOT:
        return
    fig, ax = plt.subplots()
    x = list(range(len(y)))
    ax.scatter(x, y)
    for i, txt in enumerate(labels):
        ax.annotate(txt, (x[i], y[i]))
    plt.show()

# "warm up" CPU and code paths
[time_input(" " * 13) for i in range(20)]

# Find length of password.
# For this, we try strings of different length.
# The one that takes the most amount of time is likely the password length!
times = [time_input(" " * i) for i in range(20)]
scatter_plot(times, list(range(20)))
password_length = max(enumerate(times), key=lambda x: x[1])[0] # don't worry, just gets the index in "times" with the highest value 
print("length:", password_length)

# Bruteforce password character by character.
# For this, we time how long it takes for each character if we append it to the already known password prefix 
# and pad it to the already known password length.
# As the timing difference is way smaller than for the password length, we repeat the measurement for each character 10 times.
# Since we want to spread noise evenly over all characters, we measure each character once and do that 10 times.
# (Instead of measuring the first character 10 times, then the second character 10 times, etc.)
# We use the median to decide which character is the correct one as the median should do a good job of removing outliers.
known_part = ""
for i in range(password_length - 1):
    times = [[] for _ in string.printable]
    for k in range(10):
        for j,p in enumerate(string.printable):
            times[j].append(time_input(known_part + p  + " " * (password_length - len(known_part) - 1)))
    medians = [statistics.median(t) for t in times]
    scatter_plot(medians, string.printable)
    known_part += string.printable[max(enumerate(medians), key=lambda x: x[1])[0]] # don't worry, just gets the character that took longest

# There is no real timing difference for the last character (as there is no additional loop iteration either way),
# so we just guess it and use the check_password output as feedback.
for p in string.printable:
    if check_password(known_part + p):
        print(f"Found Password: {known_part + p} with {TOTAL_ATTEMPTS} attempts")
        break
else:
    print("Password not found :(")
