# Title: Interactive Password Strength Checker and Policy Auditor
# Author: Hiba Rabhi
# Date created: October 20, 2026
# Last updated: November 2, 2026

# Description: Checks a password against a security policy and rates its strength

# How to run: python password_checker.py

import string

# The password policy
MIN_LENGTH = 8

# A list of very common passwords that shouldn't be used
COMMON_PASSWORDS = [
    'password', '123456', '12345678', 'qwerty', 'abc123',
    '111111', 'letmein', 'admin', 'welcome', 'iloveyou',
]
# DONT FORGET DOCTEST AT THE END
# Helper functions

def has_lowercase(password):
    '''
    (str) -> bool
    Checks if the password contains a lowercase letter
    
    Examples:
    >>> has_lowercase('password')
    True

    >>> has_lowercase('1 2 3')
    False

    >>> has_lowercase('PASSWORd')
    True
    '''
    for char in password:
        if char.islower():
            return True
    return False


def has_uppercase(password):
    '''
    (str) -> bool
    Checks if the password contains an uppercase letter
    
    Examples:
    >>> has_uppercase('password')
    False
    
    >>> has_uppercase('admiN')
    True
    
    >>> has_uppercase('12Admin')
    True
    '''
    for char in password:
        if char.isupper():
            return True
    return False


def has_digit(password):
    '''
    (str) -> bool
    Checks if the password contains a number
    
    Examples:
    >>> has_digit('password1')
    True

    >>> has_digit('admin')
    False

    >>> has_digit('56ADMIn')
    True
    '''
    for char in password:
        if char.isdigit():
            return True
    return False


def has_symbol(password):
    '''
    (str) -> bool
    Checks if the password contains a special character
    
    Examples:
    >>> has_symbol('letmein')
    False

    >>> has_symbol('admin!')
    True

    >>> has_symbol('12_3_admin')
    True
    '''
    for char in password:
        if char in string.punctuation: # !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
            return True
    return False


def has_space(password):
    '''
    (str) -> bool
    Checks if the password contains a space
    
    Examples:
    >>> has_space('password ')
    True

    >>> has_space('admin123')
    False

    >>> has_space('this is my password')
    True
    '''
    return ' ' in password


def is_common(password):
    '''
    (str) -> bool
    Checks if the password is common
    
    Examples:
    >>> is_common('letmeIN')
    True

    >>> is_common('admin123')
    False

    >>> is_common('WELCOME')
    True
    '''
    return password.lower() in COMMON_PASSWORDS


# Policy auditor: checks every rule and reports PASS/FAIL

def audit_policy(password):
    '''
    (str) -> list
    Checks the password against every rule of the policy.
    Returns a nested list: each inner list is [rule description, passed],
    where passed is True or False.
 
    Example:
    >>> audit_policy('Hello123')[0]
    ['At least 8 characters', True]
    
    >>> audit_policy('Wecome_admin')[3]
    ['Contains a number (0-9)', False]
    
    >>> audit_policy('#NEWPASSWORd')[4]
    ['Contains a symbol (!@#$...)', True]
    '''
    results = [
        ["At least " + str(MIN_LENGTH) + " characters", len(password) >= MIN_LENGTH],
        ["Contains a lowercase letter (a-z)", has_lowercase(password)],
        ["Contains an uppercase letter (A-Z)", has_uppercase(password)],
        ["Contains a number (0-9)", has_digit(password)],
        ["Contains a symbol (!@#$...)", has_symbol(password)],
        ["Does not contain spaces", not has_space(password)],
        ["Is not a common password", not is_common(password)],
    ]
    return results


# Strength score: 0 to 5 points

def get_score(password):
    '''
    (str) -> int
    Returns the strength score of the password, between 0 and 5
    
    Examples:
    >>> get_score('ThePasswordIsStrong #!2')
    5
    
    >>> get_score('12345')
    1
    
    >>> get_score('1#password')
    3
    '''
    if is_common(password):
        return 0 # common passwords are always the weakest
 
    score = 0
    if len(password) >= MIN_LENGTH:
        score += 1
    if len(password) >= 12: # longer passwords get bonus points
        score += 1
    if has_lowercase(password) and has_uppercase(password):
        score += 1
    if has_digit(password):
        score += 1
    if has_symbol(password):
        score += 1
    return score
 
 
def get_strength_label(score):
    '''
    (int) -> str
    Converts a strength score (from 0 to 5) into a label
    describing how strong the password is.

    Examples:
    >>> get_strength_label(0)
    'Very Weak'

    >>> get_strength_label(3)
    'Medium'

    >>> get_strength_label(5)
    'Very Strong'
    '''
    if score <= 1:
        return 'Very Weak'
    elif score == 2:
        return 'Weak'
    elif score == 3:
        return 'Medium'
    elif score == 4:
        return 'Strong'
    else:
        return 'Very Strong'
    

# Show the report to the user

def print_report(password):
    '''
    (str) -> NoneType
    Prints a full report for the given password:
    - PASS or FAIL for each rule of the policy
    - how many rules were passed and whether the policy is met
    - the strength score (0 to 5) shown as a bar, with its label
    - tips for every rule that failed
    Returns nothing.
    
    Example:
    >>> print_report('My$ecureP4ss!')

    POLICY AUDIT
    [PASS] At least 8 characters
    [PASS] Contains a lowercase letter (a-z)
    [PASS] Contains an uppercase letter (A-Z)
    [PASS] Contains a number (0-9)
    [PASS] Contains a symbol (!@#$...)
    [PASS] Does not contain spaces
    [PASS] Is not a common password

    Rules passed: 7 / 7
    Result: This password MEETS the policy.

    STRENGTH
      [#####]  5/5  ->  Very Strong

    '''
    print()
    print('POLICY AUDIT')
    results = audit_policy(password)
    passed_count = 0
 
    for result in results:
        rule = result[0] # the description (str)
        passed = result[1] # True or False (bool)
        if passed:
            print('[PASS] ' + rule)
            passed_count += 1
        else:
            print('[FAIL] ' + rule)
 
    print()
    print('Rules passed: ' + str(passed_count) + ' / ' + str(len(results)))
 
    if passed_count == len(results):
        print('Result: This password MEETS the policy.')
    else:
        print('Result: This password does NOT meet the policy.')
 
    score = get_score(password)
    bar = '#' * score + '-' * (5 - score) # simple text strength bar
    print()
    print('STRENGTH ')
    print('  [' + bar + ']  ' + str(score) + '/5  ->  ' + get_strength_label(score))
 
    # Give tips for every rule that failed
    tips = []
    for result in results:
        if not result[1]: # this rule failed
            tips.append(result[0])
    if len(tips) > 0:
        print()
        print('Tips to improve:')
        for tip in tips:
            print("  - " + tip)
    print()
 
 
# Main program
def main():
    '''
    () -> NoneType
    It keeps asking the user for a
    password and prints a report for each one, until the user
    types 'q' to quit. An empty input asks the user to try again.
    Returns nothing.
    
    Example:
    Password Strength Checker & Auditor
    Enter a password to check (or 'q' to quit): Hello123
    Enter a password to check (or 'q' to quit):
    Please type something.
    Enter a password to check (or 'q' to quit): q
    Goodbye! Stay safe online.
    '''
    print('Password Strength Checker & Auditor')
 
    while True:
        password = input('Enter a password to check (or \'q\' to quit): ')
 
        if password == 'q':
            print('Goodbye! Stay safe online.')
            break
 
        if password == '':
            print('Please type something.\n')
            continue
 
        print_report(password)

 
# Only run main() when this file is run directly
if __name__ == '__main__':
    main()