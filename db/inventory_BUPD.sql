USE `disks`;
DELIMITER $$
CREATE TRIGGER `inventory_BUPD` BEFORE UPDATE ON `inventory` FOR EACH ROW
BEGIN
	set NEW.chg_by = USER();
	set New.chg_date = NOW();
END;