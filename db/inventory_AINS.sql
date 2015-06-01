USE `disks`;
DELIMITER $$
CREATE TRIGGER `inventory_AINS` AFTER INSERT ON `inventory` FOR EACH ROW
BEGIN
	INSERT INTO history (location, vendor, product, model, serialNo, state, chg_by, chg_date, description) VALUES (new.location, new.vendor, new.product, new.model, new.serialNo, new.state, new.chg_by, new.chg_date, new.description);
END;
