from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("threatintel", "0001_initial"),
    ]

    operations = [
        migrations.AddConstraint(
            model_name="ioc",
            constraint=models.UniqueConstraint(
                fields=("value", "type", "source"),
                name="unique_ioc_value_type_source",
            ),
        ),
    ]
