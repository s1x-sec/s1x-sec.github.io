---
layout: single
title: OSCP+ Honest Review
excerpt: "OSCP certification is considered the must-have certification for any penetration tester... but is it worth giving it a try in 2026?"
date: 2026-07-08
classes: wide
header:
  teaser: /assets/images/oscp/portada.svg
  teaser_home_page: true
categories:
  - OSCP
  - Review
tags:
  - Offensive Security
  - Review
---


## Introduction

Hello everyone, when I started this blog a few years ago I always dreamed of doing this review at some point.....and I can finally do it.

In this post, you're going to see how long it actually takes to complete the theory, some of the external resources I've used, the time it took me to solve the labs, and my experience with both exam attempts and emotional management (because yes, you can fail).

## Review for Tik Tok users.

I bought the certification in December 2025 and got my pass (after failing once) in May 2026.

Since people have a short attention span lately (thanks tik tok), I'm going to quickly answer the questions you care about if you're reading this.

**How long does it take to go through all the theory and make your notes?**

It's going to depend a lot on the person, but in my case it took exactly 95 hours and 24 minutes (keeping in mind that I went through the entire syllabus except for the AWS part).

**How long does it take to do the challenge labs and document them?**

This is another good question because it depends on your technical skills and your ability to have those "moments" to deal with the guessing games in the labs, but this is exactly how long I spent on each lab:

![1]


I want to emphasize that depending on your skills and how much you like to dig deep, this time could be longer or shorter. In my case, I documented all the machines in all the labs and made diagrams to understand the lab networks (in Relia, this is very necessary).

  
**Was it hard to fail?**

Yes. 
    
Oh........you want to know more? Well, I had never failed a certification before. I was used to facing certifications where the exam was very similar to what they taught you, and in this case, the exam doesn't evaluate anything they teach you........well, they do, but their main focus is        measuring your endurance in front of a screen, your ability to handle situations where it seems like the exploit doesn't work and you're just missing one tiny piece....ultimately, they want you to be a try harder.

After the first attempt, I had a week where it didn't really affect me, but then the world came crashing down and I even thought about quitting....honestly, if you're reading this and thinking about quitting, I'm not going to tell you not to. My advice is to do whatever you think will make      you happy in that moment. For me, stopping studying and forgetting about the certification made me very happy....for those who don't know, if you fail, you have a cooldown period before you can take it again. In my case, I decided to schedule the exam for the exact first day the cooldown        ended because I needed to get it done and, whatever the result, get it out of my head.


## For non Tik Tok users


If you've made it this far, I'm guessing you want to know how I approached everything and what resources helped me pass.

**Content Management**

The syllabus has 31 modules, of which I did the ones that strictly appeared on the exam (I'm trying to complete the rest now). As I mentioned, reading the text, taking notes, and researching the techniques detailed there took me 95 hours. It might seem like a lot of boring hours, but keep in mind that throughout the syllabus there are small labs that liven up the journey.

To take notes, I used Obsidian with a bunch of plugins, and later, when Obsidian got out of hand, I created new notes in CherryTree using only the commands I used over and over again.

Since I already had a pretty solid technical foundation, I did machines from TJNull's list at the same time I was going through the syllabus. Obviously, I documented all these machines too, and always took notes on the new techniques I was seeing.

Is the whole syllabus enough to pass? Yes and no.......OffSec isn't going to teach you the exact commands needed to pass their exam, they're going to teach you the techniques that exist and the foundation of why those techniques work......from there, your task is to research, document, and test until you get a personalized cheatsheet of the things that work for you.

Talking to colleagues who were preparing for the OSCP, I realized that we all approached things differently, and that's the beautiful thing about this field: sharing and learning (which is why I'm making this blog).

**Labs**

If I had to keep just one thing from the whole certification, I would definitely choose the Challenge Labs. You start from the bottom up and you really feel like you're making progress. An example: in Secura, I got stuck for 3 hours because I didn't use nxc with the --local-auth flag, and then in a more advanced lab, I was already testing with --local-auth and without it....it seems silly, but details like that help you not fail on the small stuff on exam day (which still happens).

It's true that I don't see OSCP A, B, and C aligned with the difficulty of the exams....the standalone machines have a suitable difficulty similar to the exam ones, but the AD sets feel a bit outdated compared to the two AD sets I actually ended up solving in the exam (I don't know if the rest of the exam scenarios are easier).

**First Exam Attempt**

On the first attempt, I felt super prepared. It's true that the little imposter inside me only remembered the machines I couldn't solve and had to look up write-ups for (I'll talk about this later).

I started at 11 AM Spanish time, and within 2 hours I already had my first 20 points from a Linux machine that honestly seemed very easy to me (after solving 50 machines on Proving Grounds). The AD took a bit more effort, but once I put all the puzzle pieces together and noticed the rabbit holes, I got the 40 points, putting me at 60 points......here began a nightmare that didn't end.

Having 60 points in 4 hours gave me the peace of mind that I was going to pass, but as time went by, that peace turned into desperation. I know, I only had to gain access to one of the two remaining machines, but my scenario was complicated. I had two Windows machines left; one of them I knew I wasn't going to get because it touched on a topic I hadn't prepared for....so my chances were reduced to just one machine that looked very promising.

Reviewing my notes later, I realized what I think I failed at, and it was honestly a silly mistake. I spent over 20 hours obsessing over a machine where I was 99% of the way to getting initial access, but nerves and desperation made me overlook what I actually needed. Looking back today, I think it required a bit of a "genius moment" idea, but it wasn't technically difficult.

After trying some very crazy things (I MEAN VERY, VERY CRAZY), I didn't manage to pass, falling short by just 10 points......

Even so, I wrote the report and sent it to OffSec to get feedback on what I had missed. I didn't expect the solution, just to understand which areas I needed to improve....the response didn't clear much up for me, but at least I practiced reporting.

Days passed, and I had to face a brutal panic about failing again. I couldn't sit down to do a CTF, I couldn't review notes or solve new machines. My head was completely exhausted, which led me to take the second exam attempt without studying.

**Second Exam Attempt**

This time the exam started at 9 AM. I consider myself much more productive around 10-11 AM, which is why I always choose these kinds of times.

I started with the AD, which was the part I was strongest in, and I only got 10 points in 3 hours. The exam wasn't starting well, and all I could think about was my first attempt. When you get stuck, the best thing is to jump to something else, so I went to the standalone machines.

This time I had 2 Linux and 1 Windows. I was able to crack one of the Linux boxes in 1 hour and the other in 2 hours. That put me at 50 points and left me in a scenario I didn't expect: the AD unsolved and the standalones resolved....

I didn't want to try the last standalone machine because I had a feeling it was very complicated, and I felt like the AD couldn't possibly be that hard. After trying everything I knew for hours, it hit 11:40 PM, and I was much sadder than on the first attempt. I decided to give up on the OSCP, but not before resetting the lab and trying some attacks that I knew should work but weren't.....after resetting the AD environment and trying the attack I believed should work, I managed to jump to the second machine (I can't give many details), and from there the escalation to domain admin took less than 5 minutes, giving me 80 points...

I could say that at that moment I was happy about getting the certification, but no, I was happy because the try harder nightmare was over. Because I was finally going to be able to stop grinding Proving Grounds, doing challenge labs, and refining notes that I'm actually very proud of, by the way.

The next day I did the report, and 3 days after sending it, they confirmed I had passed.

**Resources**

As for resources, I used the OffSec material.....What!?!? No 10 additional tutorials? The truth is I don't have a track record of all the resources used. I have commands and notes that I put together as OffSec taught me the techniques needed to pass, and I think this is the beautiful part of the certification.

The summary is simple: if you just copy OffSec's commands into your notes and take the exam, you're going to fail 101% of the time. As they mention in the introduction, they want you to be a tryharder. Meaning, if I tell you that one way to move laterally is by getting a Silver Ticket, you should look for a way to practice that attack, to get the necessary data from Linux and from Windows, to use the Silver Ticket service to pivot if you could establish RCE, to access the service from a compromised Windows machine, to access it from your Linux machine, to access it from your Linux through pivoting into the internal network, etc., etc.

Are all the possibilities I just mentioned covered in the syllabus? Well, no, they aren't, but I have them in my notes.....that's where this certification wants to take you to be curious. That's why they don't let you use AI; I don't think it's because they want to complicate it, I think it's because they want to prevent someone from coming in and saying to ChatGPT, "I have this kerberoastable service user, give me lots of ideas," and after trial and error reaching the conclusion of the correct attack.

After this summary, I'll share some of the resources that helped me solve the labs and the exam, and which today are part of my toolkit for pentesting tasks:

```c
Windows PrivEsc Checklist: https://daniel10barredo.github.io/PrivEscAssist_Windows/

Linux PrivEsc Checklist: https://daniel10barredo.github.io/PrivEscAssist_Linux/

HackTricks: https://hacktricks.wiki/en/index.html

NXC (I used it for everything): https://www.hackingloops.com/netexec-cheat-sheet/

Pivoting: https://github.com/nicocha30/ligolo-ng

Shell Handler: https://github.com/brightio/penelope
```

As for my notes, I think it's something very personal, and if you don't make your own notes, you won't see the point in getting this certification.....even so, I'll leave a screenshot of the final structure of the notes that helped me pass.

![2]


## Conclusion

Is it worth paying for the OSCP? The big question that everyone who walks this path tries to answer.....honestly? It depends on your personality. We agree it's not a cheap certification and that buying it is a huge effort. If you have the money and the drive, do it....but don't do it just to get the paper, like I did. Do it to enjoy the journey, the labs, the research, and creating your own notes.....after failing the first time, the only thing that filled me with pride was looking at my notes built over 4 months that perfect tree of techniques looking exactly how I wanted them, the ones that worked for me, with tips to solve the errors I had already run into.

It is a tough certification. Out of all the ones out there, this might be one of the toughest in terms of mental demand, not so much technical. OffSec wants to test you and see how much you can endure, what your limit is, how you manage your emotions and your fatigue. We shouldn't forget that it's still an entry-level certification; meaning, you won't get technically difficult things, just weird things.....it's ultimately a 24-hour CTF where you have to have the skill and the luck to spot the solution. Failing or not seeing the solution that day doesn't mean anything (it took me a lot to accept this). If you are a professional who hasn't achieved it but has strived for it, to me, you already hold a lot of value....only someone who has tried can speak of failure.

A certification is never going to speak for your hacking level; it's simply that, a piece of paper. If I compare this experience with the work I've been doing for years, well, it has similarities: users with weak passwords, files with plaintext passwords, passwords in PowerShell and bash histories, SQLi, RCE.........but it also has many differences. They don't teach you to manage the criticality of vulns based on the needs of the environment and the client, they don't teach you to look for (simpler) things that still need to be reported, like business logic errors, HTMLi, SSRF, Open Redirect, SQLi that go nowhere because they are time-based and it's a test database....

Whatever you do will be fine. I'm not going to sell you the idea that this certification will turn you into a professional hacker with years of experience, and I can't really speak to the doors it opens in offensive security because I was already working in it.....I don't consider it essential to work as a pentester, but it might help weed out bad habits and develop your own critical thinking.

Thank you very much for reading this post, see you in the next one!

![3]



[1]:/assets/images/oscp/1.png
[2]:/assets/images/oscp/2.png
[3]:/assets/images/oscp/3.png
