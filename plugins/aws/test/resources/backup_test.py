from fix_plugin_aws.resource.backup import (
    AwsBackupJob,
    AwsBackupPlan,
    AwsBackupVault,
    AwsBackupRecoveryPoint,
    AwsBackupProtectedResource,
    AwsBackupReportPlan,
    AwsBackupRestoreTestingPlan,
    AwsBackupLegalHold,
    AwsBackupRestoreJob,
    AwsBackupCopyJob,
    AwsBackupFramework,
)
from test.resources import round_trip_for, build_graph


def test_backup_jobs() -> None:
    round_trip_for(AwsBackupJob)


def test_backup_plans() -> None:
    round_trip_for(AwsBackupPlan)


def test_backup_vaults() -> None:
    round_trip_for(AwsBackupVault, "vault_policy")


def test_backup_recovery_points() -> None:
    builder = build_graph(AwsBackupVault)
    assert len(list(builder.nodes(AwsBackupRecoveryPoint))) > 0


def test_backup_protected_resources() -> None:
    round_trip_for(AwsBackupProtectedResource)


def test_backup_report_plans() -> None:
    round_trip_for(AwsBackupReportPlan)


def test_backup_restore_testing_plans() -> None:
    round_trip_for(AwsBackupRestoreTestingPlan)


def test_backup_legal_holds() -> None:
    round_trip_for(AwsBackupLegalHold)


def test_backup_restore_jobs() -> None:
    round_trip_for(AwsBackupRestoreJob)


def test_backup_copy_jobs() -> None:
    round_trip_for(AwsBackupCopyJob)


def test_backup_frameworks() -> None:
    round_trip_for(AwsBackupFramework)
