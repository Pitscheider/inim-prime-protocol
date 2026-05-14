# Legal Notice
## Table of Contents

1. [Purpose of This Document](#purpose-of-this-document)
2. [Author's Position](#authors-position)
3. [What This Repository Contains](#what-this-repository-contains)
4. [Applicable EU Law](#applicable-eu-law)
5. [Inim Prime/STUDIO EULA (version 4.07)](#inim-prime-studio-eula-version-407)
6. [Analysis of the EULA in Light of EU Law](#analysis-of-the-eula-in-light-of-eu-law)
7. [What This Software Is Not](#what-this-software-is-not)
8. [Trademarks](#trademarks)
9. [No Warranty](#no-warranty)
10. [Intended Use and Misuse Disclaimer](#intended-use-and-misuse-disclaimer)
11. [License](#license)
12. [Good Faith Statement](#good-faith-statement)
13. [Contact](#contact)


## Purpose of This Document

This document explains the legal basis for this project and the intent behind its publication. It is written to be transparent about what this software is, how it was developed, and why its publication is lawful. It addresses directly the applicable EU legislation, the EULA of the software observed during research, and the relationship between the two.

---

## Author's Position

The author is a private individual and end user residing in the European Union. The author owns an Inim Prime alarm panel installed on their premises. The author obtained Inim Prime/STUDIO version 4.07 from the internet for the purpose of configuring and managing their own panel. The author is not a professional installer, is not affiliated with Inim Electronics s.r.l. in any capacity, and has no commercial, contractual, or working relationship with Inim Electronics s.r.l. of any kind.

No compensation was received for this work. No commercial product is being developed. The sole purpose of this project is personal home automation and the sharing of protocol research with other end users in the same situation.

---

## What This Repository Contains

This repository contains a Python library that implements a communication protocol for Inim Prime alarm panels. The protocol implementation was developed through analysis of network communications exchanged between `Inim Prime/STUDIO` and an `Inim Prime panel` owned by the author, using Wireshark.

No proprietary source code, firmware, or binaries belonging to Inim Electronics s.r.l. were decompiled, disassembled, modified, or reproduced at any stage. The understanding of the protocol was derived from observing the content of network packets transmitted across the author's own local network, while running the software in the ordinary manner for which it is intended.

---

## Applicable EU Law
> *The following discussion reflects the author's understanding of European Union
> law and is provided for transparency and informational purposes only. It should
> not be construed as legal advice. Readers with specific legal concerns are
> encouraged to consult a qualified legal professional.*

### Directive 2009/24/EC on the Legal Protection of Computer Programs

The primary legal basis for the observation work performed in this project is **Article 5(3)** of _Directive 2009/24/EC of the European Parliament and of the Council of 23 April 2009 on the legal protection of computer programs_.

The directive is available at https://eur-lex.europa.eu/eli/dir/2009/24/oj/, an official website of the European Union.
The full text of the relevant articles is reproduced below.

---

> #### Article 4 - Restricted acts
> 1.   Subject to the provisions of Articles 5 and 6, the exclusive rights of the rightholder within the meaning of Article 2 shall include the right to do or to authorise:
>     - _(a)_ the permanent or temporary reproduction of a computer program by any means and in any form, in part or in whole; in so far as loading, displaying, running, transmission or storage of the computer program necessitate such reproduction, such acts shall be subject to authorisation by the rightholder;
>     - _(b)_ the translation, adaptation, arrangement and any other alteration of a computer program and the reproduction of the results thereof, without prejudice to the rights of the person who alters the program;
>     - _(c)_ any form of distribution to the public, including the rental, of the original computer program or of copies thereof.
> 2.   The first sale in the Community of a copy of a program by the rightholder or with his consent shall exhaust the distribution right within the Community of that copy, with the exception of the right to control further rental of the program or a copy thereof.

---

#### Article 5 - Exceptions to the restricted acts
> 1.   In the absence of specific contractual provisions, the acts referred to in points (a) and (b) of Article 4(1) shall not require authorisation by the rightholder where they are necessary for the use of the computer program by the lawful acquirer in accordance with its intended purpose, including for error correction.
> 2.   The making of a back-up copy by a person having a right to use the computer program may not be prevented by contract in so far as it is necessary for that use.
> 3.   The person having a right to use a copy of a computer program shall be entitled, without the authorisation of the rightholder, to observe, study or test the functioning of the program in order to determine the ideas and principles which underlie any element of the program if he does so while performing any of the acts of loading, displaying, running, transmitting or storing the program which he is entitled to do.

---
#### Article 6 — Decompilation
> 1.   The authorisation of the rightholder shall not be required where reproduction of the code and translation of its form within the meaning of points (a) and (b) of Article 4(1) are indispensable to obtain the information necessary to achieve the interoperability of an independently created computer program with other programs, provided that the following conditions are met:
>     - _(a)_ those acts are performed by the licensee or by another person having a right to use a copy of a program, or on their behalf by a person authorised to do so;
>     - _(b)_ the information necessary to achieve interoperability has not previously been readily available to the persons referred to in point (a); and
>     - _(c)_ those acts are confined to the parts of the original program which are necessary in order to achieve interoperability.
> 2.   The provisions of paragraph 1 shall not permit the information obtained through its application:
>     - (a) to be used for goals other than to achieve the interoperability of the independently created computer program;
>     - _(b)_ to be given to others, except when necessary for the interoperability of the independently created computer program; or
>     - _(c)_ to be used for the development, production or marketing of a computer program substantially similar in its expression, or for any other act which infringes copyright.
> 3.   In accordance with the provisions of the Berne Convention for the protection of Literary and Artistic Works, the provisions of this Article may not be interpreted in such a way as to allow its application to be used in a manner which unreasonably prejudices the rightholder's legitimate interests or conflicts with a normal exploitation of the computer program.

---

#### Article 8 — Continued application of other legal provisions
> The provisions of this Directive shall be without prejudice to any other legal provisions such as those concerning patent rights, trade-marks, unfair competition, trade secrets, protection of semi-conductor products or the law of contract.
>
> Any contractual provisions contrary to Article 6 or to the exceptions provided for in Article 5(2) and (3) shall be null and void.

---

### How These Articles Apply to This Project

-   **Article 5(3)** is the primary basis for the observation work.
    > The person having a right to use a copy of a computer program shall be entitled, without the authorisation of the rightholder, to observe, study or test the functioning of the program in order to determine the ideas and principles which underlie any element of the program if he does so while performing any of the acts of loading, displaying, running, transmitting or storing the program which he is entitled to do.
    
    The author ran `Inim Prime/STUDIO` in the ordinary way, loading and running it as intended, and observed the network traffic it produced. This is the type of conduct Article 5(3) was enacted to permit: observing, studying, and testing the functioning of a program while performing acts the user is entitled to perform. No decompilation, disassembly, or reproduction of code took place. Article 5(3) has one condition: the person must have a right to use a copy of the program. The author obtained `Inim Prime/STUDIO` and used it to manage their own panel for personal use, in accordance with its EULA. The author believes this condition is satisfied.

-   **Article 6** covers decompilation specifically and is included here for completeness, because its interoperability rationale is directly relevant to the purpose of this project even though decompilation was not performed. The author did not reproduce or translate the code of `Inim Prime/STUDIO`, so Article 6 is not the operative provision. However, its purpose, enabling interoperability between independently created programs, is the same as the purpose of this project, and the conditions of Article 6(1)(a), (b), and (c) are satisfied in any case.

    > - _(a)_ those acts are performed by the licensee or by another person having a right to use a copy of a program, or on their behalf by a person authorised to do so;
    > - _(b)_ the information necessary to achieve interoperability has not previously been readily available to the persons referred to in point (a); and
    > - _(c)_ those acts are confined to the parts of the original program which are necessary in order to achieve interoperability.

    - _(a)_ The author used the software solely for personal use, in accordance with the `Inim Prime/STUDIO` EULA.
    - _(b)_ No complete public specification of the native protocol was available. The HTTP API requires additional hardware (`Inim Prime LAN`), is significantly slower than the native protocol, and does not expose the full set of operations useful for a home automation integration. Furthermore, the firmware version available when this project started (4.07) was unable to handle certain operations that the HTTP API would otherwise support, such as output management.
    - _(c)_ Only the network-level protocol was studied, nothing beyond what was necessary.

    Article 6(2)(b) further specifies that information gathered through this process may be shared when necessary for the interoperability of an independently created program, which is consistent with publishing a home automation integration library.
    > - _2._ The provisions of paragraph 1 shall not permit the information obtained through its application:
    >     - _(b)_ to be given to others, except when necessary for the interoperability of the independently created computer program; or

-   **Article 8** states that any contractual provision contrary to Article 5(3) or Article 6 is null and void.
    > The provisions of this Directive shall be without prejudice to any other legal provisions such as those concerning patent rights, trade-marks, unfair competition, trade secrets, protection of semi-conductor products or the law of contract.
    >
    > Any contractual provisions contrary to Article 6 or to the exceptions provided for in Article 5(2) and (3) shall be null and void.

    The Directive provides that contractual provisions contrary to these exceptions are null and void. As addressed in the section below, the EULA of `Inim Prime/STUDIO` contains a clause prohibiting reverse engineering. To the extent that clause purports to restrict conduct protected by Article 5(3), it has no legal effect under Article 8.

---

## Inim Prime Studio EULA (version 4.07)

The End-User Licence Agreement of `Inim Prime/STUDIO` version 4.07, the software observed during the research for this project, is reproduced in full below. It is included here in the interest of full transparency and to allow the reader to evaluate the relationship between its terms and the EU legal framework described above.

---

> #### End-User Licence Agreement (EULA)
> This is a legally binding agreement between the authors of this software (INIM Electronics s.r.l.) and You (You means the licensee or anyone engaged by You or otherwise pertaining to You). By installing, copying or otherwise using this software, You acknowledge that You have read, understand and agree to be bound by the terms of this agreement (EULA). If You do not agree with any of the terms or conditions of this agreement (EULA), You are not authorised to install or use this software for any purpose whatsoever. All versions of this software are protected throughout the world by copyright and other intellectual property rights. You may not duplicate, sell, distribute or use this software save as provided under this End-User Licence Agreement, unless You obtain written consent from INIM Electronics s.r.l.. Any parties  interested in using this software for non-personal purposes must contact INIM Electronics s.r.l..
> 
> #### Rights
> You are not permitted to reverse engineer, disassemble, decompile or modify this product or any portion thereof.
>
> #### Reproduction and distribution
>This End-User Licence Agreement hereby grants to You the right to reproduce and distribute an unlimited number of copies of this product; each copy must be in whole and accompanied by a copy of this agreement (EULA). You may not embed this software in another software  application or freeware, shareware or commercial product without first obtaining explicit consent from INIM Electronics s.r.l..
> 
> #### Other rights and Restrictions
> You are not permitted to reverse engineer, disassemble, decompile or modify this product or any portion thereof.
>
> #### Separation of components
> This software is Licensed as a single product; You are not permitted to separate and use any portion of it on more than one single workstation.
> 
> #### Transfer of the Software
> You are permitted to transfer this product and Your rights under this End-User Licence
Agreement on a permanent basis to another person or entity.
> 
> #### Licence Term
> Your rights under this agreement (EULA) will terminate immediately if You fail to comply with any of the terms and conditions contained within. If this occurs, You must destroy the Software, and all copies of all and any part of it. By using this software, You agree to be bound by the terms of this End-User Licence Agreement.
> 
> #### Copyright
> ith [sic] the exception of any explicit annotations, all rights and the copyright pertaining to the software in its entirety and its parts (including figures, photographs, animation, video, audio, music, text and code) and accompanying documentation are the exclusive property of INIM Electronics s.r.l.. This software is protected by International Copyright Laws and Agreements and must be considered in the same way as all other material which is subject to copyright laws.
>
> #### Disclaimer of warranties
> INIM Electronics s.r.l. make no warranties of any kind, either statutory or otherwise in relation to this product. The software and all associated material is released without any undertakings of any kind, express or implied. You use this product at your own risk. 
>
> #### Disclaimer of liabilities
> In no event shall the authors of this software (INIM Electronics s.r.l.) be liable to You or to those claiming for You for any damage of any kind, whether direct or in direct [sic] (including but not limited to, damage or loss of any kind, loss of profits, business interruptions, loss or corruption of data) arising out of or in connection with the use of, or the impossibility to use, this product.
> 
> Contact http://www.inim.biz for further details.

---

## Analysis of the EULA in Light of EU Law

### The reverse engineering prohibition

The EULA states twice: 
> You are not permitted to reverse engineer, disassemble, decompile or modify this product or any portion thereof.

This clause is acknowledged. It does not, however, apply to the conduct underlying this project, for two reasons.

**First**, the conduct underlying this project did not involve decompilation, disassembly, modification, or reproduction of the software itself. The author used `Inim Prime/STUDIO` in its ordinary manner and observed the network communications it generated while interacting with the author's own hardware. The resulting protocol implementation was developed from analysis of those communications for interoperability purposes.

**Second**, even if the conduct described above were characterised as reverse engineering, Directive 2009/24/EC provides that contractual provisions contrary to Articles 5(2), 5(3), or 6 are “null and void”:
> Any contractual provisions contrary to Article 6 or to the exceptions provided for in Article 5(2) and (3) shall be null and void.

Articles 5(3) and 6 of the Directive recognise, under specific conditions, the right of a lawful user to observe, study, and test the functioning of a program, and to obtain information necessary to achieve interoperability with independently created software. To the extent a contractual provision purports to prohibit conduct protected by those provisions, the Directive states that such a provision is without legal effect.

The purpose of this project is interoperability: enabling independently developed software to communicate with hardware owned by the user. The protocol analysis performed for this project was limited to information necessary to understand and implement that interoperability, and did not involve reproduction of proprietary source code or firmware.

### Personal use

The EULA states:
> Any parties  interested in using this software for non-personal purposes must contact INIM Electronics s.r.l..

The software was used solely in connection with the author's personally owned `Inim Prime panel`, installed on private premises, and for non-commercial purposes. The author is not a professional installer, reseller, or service provider, and has no commercial relationship with Inim Electronics s.r.l.. The use described in this repository was limited to personal configuration, management, and interoperability research relating to the author's own hardware.

### Distribution

The EULA states:
>This End-User Licence Agreement hereby grants to You the right to reproduce and distribute an unlimited number of copies of this product; each copy must be in whole and accompanied by a copy of this agreement (EULA). You may not embed this software in another software  application or freeware, shareware or commercial product without first obtaining explicit consent from INIM Electronics s.r.l..

This repository does not host `Inim Prime/STUDIO`, though a link to an external location where it can be obtained may be provided in the README for convenience. The repository does not embed or redistribute `Inim Prime/STUDIO` as part of another software product, and contains only independently developed source code intended to interoperate with `Inim Prime panel`.

---

## What This Software Is Not

- This software does not decompile, disassemble, reproduce, or modify any part of `Inim Prime/STUDIO`
- This software does not circumvent any copy protection, DRM, or access control mechanism.
- This software is not intended to provide unauthorized access to alarm systems or third-party devices.
- This software does not contain any code, data, or assets decompiled from Inim Electronics' software or firmware.
- This software is not a competing product. It was developed for non-commercial purposes and is distributed free of charge. It is not distributed for profit.
- The author has no affiliation, employment, or contractual relationship with Inim Electronics s.r.l.

---

## Trademarks

"Inim", "Inim Prime", and "Inim Prime/STUDIO" are trademarks or registered trademarks of Inim Electronics s.r.l. Their use in this repository is purely referential, to identify the hardware and software with which this library is designed to interoperate. No affiliation with, endorsement by, or sponsorship by Inim Electronics s.r.l. is claimed or implied.

---

## No Warranty
This software is provided as-is, without warranty of any kind, express or implied. The author makes no guarantees regarding its correctness, reliability, completeness, or fitness for any particular purpose. Use of this library may affect the configuration or behaviour of your alarm panel. The author accepts no responsibility for any damage, data loss, unintended arming or disarming, or any other consequence arising from its use. You use this software entirely at your own risk.

---

## Intended Use and Misuse Disclaimer
This library is intended solely to enable interoperability between Inim Prime alarm panels and home automation software, on devices and systems lawfully owned or operated by the user. It is not intended to facilitate unauthorised access to alarm systems, bypass installer-level controls, defeat security protections, or interact with any system the user does not own or have explicit permission to operate. The author condemns any use of this software for unauthorised access to third-party systems and accepts no responsibility for such use.

---

## License

This software is released under the **GNU General Public License v3.0 (GPL-3.0)**. See the `LICENSE` file for the full text.

The GPL-3.0 was chosen deliberately. It ensures that:

- The source code remains open and auditable by anyone, including Inim Electronics s.r.l.
- Any derivative work that is distributed must also be open source.
- The software cannot be incorporated into proprietary products without disclosing the source.

This licensing choice is consistent with the interoperability purpose of the project and reflects the author's commitment to full transparency.

---

## Good Faith Statement

This project was undertaken in good faith, for personal benefit and to share protocol research with other end users of Inim hardware. The author has no intent to harm Inim Electronics s.r.l. commercially or reputationally. The author is a customer of Inim alarm hardware who wishes to integrate their own panel with open home automation software, a common and legitimate need that Inim does not officially support.

The author believes that end users have a legitimate interest in making their own hardware work with software of their choosing, and that the law of the European Union agrees.

---

## Contact

If Inim Electronics s.r.l. or any other party has a legal concern regarding this repository, the author can be contacted via the GitHub issue tracker or the contact information associated with the GitHub account. The author is willing to engage in good-faith dialogue to resolve any concern that does not require the suppression of lawful interoperability research.
