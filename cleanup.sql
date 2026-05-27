-- Remove duplicate team_members (keep lowest id per name)
DELETE FROM team_members WHERE id NOT IN (
  SELECT MIN(id) FROM team_members GROUP BY name
);

-- Remove duplicate press_mentions (keep lowest id per year+project+source)
DELETE FROM press_mentions WHERE id NOT IN (
  SELECT MIN(id) FROM press_mentions GROUP BY year, project_name, source
);

-- Remove duplicate approach_pillars (keep lowest id per num)
DELETE FROM approach_pillars WHERE id NOT IN (
  SELECT MIN(id) FROM approach_pillars GROUP BY num
);

-- Remove duplicate approach_stages (keep lowest id per num)
DELETE FROM approach_stages WHERE id NOT IN (
  SELECT MIN(id) FROM approach_stages GROUP BY num
);

-- Remove duplicate approach_principles (keep lowest id per yes_tr)
DELETE FROM approach_principles WHERE id NOT IN (
  SELECT MIN(id) FROM approach_principles GROUP BY yes_tr
);

-- Remove duplicate approach_materials (keep lowest id per name_tr)
DELETE FROM approach_materials WHERE id NOT IN (
  SELECT MIN(id) FROM approach_materials GROUP BY name_tr
);

-- Remove duplicate project_key_facts (keep lowest id per project+key)
DELETE FROM project_key_facts WHERE id NOT IN (
  SELECT MIN(id) FROM project_key_facts GROUP BY project_id, key_tr
);

-- Remove duplicate project_materials (keep lowest id per project+name)
DELETE FROM project_materials WHERE id NOT IN (
  SELECT MIN(id) FROM project_materials GROUP BY project_id, name_tr
);

-- Remove duplicate project_credits (keep lowest id per project+role)
DELETE FROM project_credits WHERE id NOT IN (
  SELECT MIN(id) FROM project_credits GROUP BY project_id, role_tr
);
