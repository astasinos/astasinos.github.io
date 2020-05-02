---
layout: single
title:  "Wintermute - Vulnhub"
path: /posts/
date:   2020-05-02 
tags: LFI Pivoting Tomcat RCE
categories: Vulnhub
classes: wide
author: komodino
excerpt: "Wintermute is an intermediate box. It's actually two boxes, one is Straylight and the other Necromancer. You have to acquire root on Straylight first and then pivot to Necromancer since it is located in a different subnet. Vulnerabilities included combining LFI with Mail log injection to achieve RCE in Straylight and a simple tomcat exploit for Secromancer. Priv esc was easy on both machines. Straylight had a vulnerable version of a SUID binary called screen and Necromancer a kernel exploit."
header:
  teaser: /assets/images/wintermute/wintermute.png
  teaser_home_page: true
  overlay_image: /assets/images/wintermute/wintermute.png
  overlay_filter: 0.5
---

