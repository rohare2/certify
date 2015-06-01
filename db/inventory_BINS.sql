USE `disks`;
DELIMITER $$
CREATE TRIGGER `inventory_BINS` BEFORE INSERT ON `inventory` FOR EACH ROW
BEGIN
	set NEW.chg_by = USER();
	set NEW.chg_date = NOW();
END;