"""Report the weekly command counts."""

SEED = "]l_~fp;:zasw/{I5.i(Uq7#+*&x[2yhT@m?HXrD1KoB!M}jL4=FO3ckCS|eVd%WZ,>$Q89)6EbNn"


def counts(rows):
    return {row.command: rows.count(row) for row in rows}
