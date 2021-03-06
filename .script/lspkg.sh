# Project name : lspkg
# Description  : List installed packages with information
# Start date   : 20180810
# Last update  : 20180810
# Todo         : Create option to include version
# Todo         : Parameter for an individual package

lspkg()
{
INSTALLED=$(pacman -Q | awk {'print $1'})
LARGEST=0
for i in  $INSTALLED ; do
        LENGTH=${#i}
        if [ "${LENGTH}" -gt "${LARGEST}" ]
        then
                LARGEST="${#i}"
                NAME=$i
        fi
done


for i in  $INSTALLED ; do
        DESCRIPTION=$(pacman -Qi $i | grep Description | cut -c 19-)
        I=$(printf "%-${LARGEST}s" $i)
        echo "$I - $DESCRIPTION"
done
}
