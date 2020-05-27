clc;
clear;
import java.security.*;
import java.math.*;

wienersAttack(2^16);

function p= prime_random(size)
%generates prime random number less
%than size value
while 1
p=randi(size);
if isprime(p)
    break;
end
end
end


function p=randomNumber(max)
%generates random number less
%than max value
while 1
    a=de2bi(max);
    p=randi([0 1],1,length(a));
    p=bi2de(p);
    if p<max && p>1
        break;
    end
end
end

function [a,exist]= multInverse(b,m)
[div,c1,c2] = gcd(b,m);
% returns the greatest common divisor
%"div" and the two integer constants that solve
% c1*b + c2*m = div

if div==1
    exist=1;
    a = mod(c1,m);
else
    exist=0;
    a=-1;
end
end


function [N,e,d,p,q,phi_N]=vulnarableKey(size)
%generates keypairs which are vulnarable
%to Wiener's ATTACK!!
while 1
    p=prime_random(size/2);
    q=prime_random(size/2);
    if q<p && q<2*p
        break;
    end
end


N=(p*q);
phi_N=(p-1)*(q-1);
%max d according to Wiener's Theorem
max_d=floor((1/3)*double(N)^(1/4));
while 1
    d=randomNumber(max_d);
    [e,coprime]= multInverse(d,phi_N);
    if coprime && mod((e*d),phi_N)==1
        break;
    end
end
end

function hash = num2hash(n)
%hashes the integer according to 'sha-1'
string=int2str(n);
persistent md
if isempty(md)
    md = java.security.MessageDigest.getInstance('SHA-1');
end
hash = sprintf('%2.2x', typecast(md.digest(uint8(string)), 'uint8')');
end


function e=continuedFractions(m,n)
% calculates the continued Fractions of m/n
e=[];
a=int16(floor(m/n));
b=mod(m,n);
e=[e a];
while b~=0
    m=n;
    n=b;
    a=int16(floor(m/n));
    b=mod(m,n);
    e=[e a];
    
end
end
function [n,d]=convergents(e)
%does rational approximation using 
%continued fractions.
n=[];
d=[];
for i=1:length(e)
    if i==1
        n=[n e(1)];
        d=[d 1];
    elseif i==2
        d=[d e(2)];
        n=[n e(1)*e(2)+1];
    else
        n=[n e(i)*n(i-1)+n(i-2)];
        d=[d e(i)*d(i-1)+d(i-2)];
    end
            
end
end

function wienersAttack(size)
%whole Attack Flow of Wiener!!
[N,e,d,p,q,phi]=vulnarableKey(2^16);
isSuccess=0;
fprintf('Vulnerable RSA keys are generated. \n');

hash_N=num2hash(N);
hash_e=num2hash(e);
hash_d=num2hash(d);

fprintf('Hashed N value -->  %s \n',hash_N);
fprintf('Hashed e value -->  %s \n',hash_e);
fprintf('Hashed d value -->  %s \n',hash_d);

contFrac=continuedFractions(e,N);
[numer,denom]=convergents(contFrac);

%iterating over possible k,d values
for i=1:length(denom)
    psbl_k=numer(i);
    psbl_d=denom(i);
    if psbl_k==0
        continue;
    end
    % checking the guess values
    message=randi(1024);
    crypt_msg=int64(powermod(message,e,N));
    if message==powermod(crypt_msg,psbl_d,N)
        %the true value is found.
        hash_d_found=num2hash(psbl_d);
        fprintf('Wiener Attack Succeed!!! \n');
        fprintf('Found Hashed d value -->  %s \n',hash_d_found);
        isSuccess=1;
        break;
    end
end
%print failure
if isSuccess==0
    fprintf('Wiener Attack Failed!!');
end
end

