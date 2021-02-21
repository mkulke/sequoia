#! /bin/bash

set -e

for f in $@; do
    sq inspect --certifications "$f" \
        | awk -F': *' '
          $1 ~ /Fingerprint/ {
            fpr = $2;
            fpr_printed = 0;
          }
          $1 ~ /UserID/ {
            userid = $2;
            email = gensub(/<(.*)>/, "\\1", "", userid);
            var = email;
            sub("[@].*", "", var);
            gsub("[-@.]", "_", var);

            # printf("userid: %s\n", userid);
            # printf("email: %s\n", email);
            # printf("var: %s\n", var);

            if (fpr_printed == 0) {
                printf("\n        let %s_fpr: Fingerprint =\n\            \"%s\"\n           .parse().expect(\"valid fingerprint\");\n", var, fpr);
                fpr_printed = 1;
            }
            printf("        let %s_uid\n            = UserID::from(\"%s\");\n", var, userid);
        }
        $1 ~ /Alleged certifier/ {
            printf("        // Certified by: %s\n", $2);
        }
'
done 2>/dev/null
